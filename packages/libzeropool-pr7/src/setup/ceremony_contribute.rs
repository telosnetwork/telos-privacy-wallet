//! Offline Phase 2 stage production. No operation here qualifies a ceremony.
//! The operator and OS must protect the machine, entropy, and retained stages.
use super::{ceremony_input::{self, Layout}, circuit_identity};
use fawkes_crypto::{backend::bellman_groth16::{BellmanCS, engines::Bn256}, circuit::cs::BuildCS, engines::bn256::Fr};
use fawkes_crypto_phase2::parameters::{verify_contribution, MPCParameters};
use libzeropool_zkbob::clap::Clap;
use rand::{rngs::OsRng, RngCore};
use rand04::{ChaChaRng, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{ffi::CString, fs::File, io::{self, Read, Write}, os::unix::{ffi::OsStrExt, fs::{MetadataExt, PermissionsExt}, io::{AsRawFd, FromRawFd}}, path::{Component, Path, PathBuf}};
use zeroize::Zeroize;

const MAX_ENTROPY_BYTES: u64 = 4096;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const STAGE_FILE: &str = "mpc-params.bin";
const RECEIPT_FILE: &str = "stage-receipt.json";
const STATEMENT_FILE: &str = "participant-statement.json";
const TRUST_ASSUMPTIONS: &[&str] = &[
    "independently approved source, radix and predecessor digest",
    "trusted offline host and OS",
    "independent participant destroys secret randomness",
    "coordinator authenticates signed statements and retained stage chain",
];

#[derive(Clap)]
pub struct InitializeOpts {
    #[clap(long)] pub circuit: String,
    /// Directory containing the independently approved public radix file.
    #[clap(long)] pub radix: PathBuf,
    #[clap(long)] pub expected_radix_sha256: String,
    #[clap(long)] pub expected_identity: String,
    /// New, private stage directory. It must not exist.
    #[clap(long)] pub stage_directory: PathBuf,
}

#[derive(Clap)]
pub struct ContributeOpts {
    #[clap(long)] pub circuit: String,
    #[clap(long)] pub before: PathBuf,
    #[clap(long)] pub before_receipt: PathBuf,
    /// Digest independently approved for this predecessor, not copied from it.
    #[clap(long)] pub expected_before_sha256: String,
    #[clap(long)] pub expected_identity: String,
    #[clap(long)] pub expected_radix_sha256: String,
    /// One-based stage number; stage zero is unsafe initialization.
    #[clap(long)] pub stage_index: usize,
    /// Preopened private descriptor (3 or greater), read until EOF; never pass entropy in argv or env.
    #[clap(long, default_value = "3")] pub entropy_fd: i32,
    /// New, private stage directory. It must not exist.
    #[clap(long)] pub stage_directory: PathBuf,
}

#[derive(Clap)]
pub struct VerifyTransitionOpts {
    #[clap(long)] pub circuit: String,
    #[clap(long)] pub before: PathBuf,
    #[clap(long)] pub after: PathBuf,
    #[clap(long)] pub after_receipt: PathBuf,
    #[clap(long)] pub expected_before_sha256: String,
    #[clap(long)] pub expected_after_sha256: String,
    #[clap(long)] pub expected_identity: String,
    #[clap(long)] pub expected_radix_sha256: String,
    #[clap(long)] pub stage_index: usize,
}

fn invalid(message: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn require(condition: bool, message: &'static str) -> io::Result<()> {
    if condition { Ok(()) } else { Err(invalid(message)) }
}
fn hex32(value: &str) -> bool { ceremony_input::valid_sha256(value) }
fn ensure_profile(circuit: &str, identity: &str, radix: &str) -> io::Result<()> {
    require(matches!(circuit,"transfer" | "tree_update"), "contribution CLI supports only transfer or tree_update")?;
    require(hex32(identity) && hex32(radix), "identity/radix digest must be lowercase SHA256")?;
    require(cfg!(feature="cli_libzeropool_setup") && cfg!(feature="in3out127")
        && !cfg!(feature="in1out127") && !cfg!(feature="in7ount127")
        && !cfg!(feature="in15out127"), "unsupported ceremony build features")
}
fn compiled(circuit: &str, expected_identity: &str) -> Result<(fawkes_crypto::circuit::cs::RCS<BuildCS<Fr>>, Value), Box<dyn std::error::Error>> {
    let (cs, metadata) = circuit_identity::build(circuit)?;
    let identity = circuit_identity::describe(&cs.borrow(), metadata, io::sink())?;
    require(identity["identity_sha256"] == expected_identity, "compiled circuit identity differs from approved pin")?;
    Ok((cs, identity))
}
fn layout(cs: &fawkes_crypto::circuit::cs::RCS<BuildCS<Fr>>, count: usize) -> io::Result<Layout> {
    let cs=cs.borrow();
    Layout::stage(cs.num_input, cs.num_aux, cs.gates.len(), count)
}
fn ceremony_id(circuit: &str, identity: &str, radix: &str) -> String {
    let mut digest=Sha256::new();
    digest.update(b"telos-privacy-phase2-v1\0");
    digest.update(&(circuit.len() as u32).to_be_bytes());
    digest.update(circuit.as_bytes());
    digest.update(hex::decode(identity).expect("validated identity"));
    digest.update(hex::decode(radix).expect("validated radix"));
    hex::encode(digest.finalize())
}
fn source_lock_digest() -> String {
    hex::encode(Sha256::digest(include_bytes!("../../formal/ceremony-source-lock.json")))
}
fn lock_digest() -> String { hex::encode(Sha256::digest(include_bytes!("../../Cargo.lock"))) }

/// Output creation is anchored to a no-follow parent directory descriptor.
/// A stage is never replaced. A failed operation may leave an incomplete private
/// directory, which has no successful receipt and must be quarantined.
struct StageDirectory { path: PathBuf, dir: File }
impl StageDirectory {
    fn new(path: &Path) -> io::Result<Self> {
        let name=match path.components().last() {
            Some(Component::Normal(name)) => CString::new(name.as_bytes()).map_err(|_| invalid("NUL in stage name"))?,
            _ => return Err(invalid("stage path must end in a new directory name")),
        };
        let parent_path=path.parent().filter(|v| !v.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let parent=ceremony_input::open_checked_directory(parent_path)?;
        // SAFETY: parent is an open directory and name is NUL-terminated.
        let result=unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0 { return Err(io::Error::last_os_error()); }
        let fd=unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let dir=unsafe { File::from_raw_fd(fd) };
        let metadata=dir.metadata()?;
        require(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0, "stage directory is not private and owned")?;
        parent.sync_all()?;
        Ok(Self { path:path.to_owned(), dir })
    }
    fn create(&self, name: &str) -> io::Result<File> {
        let name=CString::new(name).map_err(|_| invalid("invalid stage filename"))?;
        let fd=unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn write_json(&self, name: &str, value: &Value) -> io::Result<()> {
        let mut file=self.create(name)?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        self.dir.sync_all()
    }
    fn write_params(&self, params: &MPCParameters) -> io::Result<()> {
        let mut file=self.create(STAGE_FILE)?;
        params.write(&mut file)?;
        file.sync_all()?;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        self.dir.sync_all()
    }
    fn path(&self, name: &str) -> PathBuf { self.path.join(name) }
}

fn receipt(identity: &Value, radix: &str, index: usize, predecessor: Option<&str>,
    stage_sha: &str, contribution: Option<&str>, validation: &Value) -> Value {
    let circuit=identity["circuit"].as_str().expect("compiled identity circuit");
    json!({
        "schema":"telos-privacy-phase2-stage-v1", "status":if index==0 {"unsafe-initialization-verified"} else {"single-transition-verified"},
        "circuit":circuit, "ceremony_id":ceremony_id(circuit,identity["identity_sha256"].as_str().unwrap(),radix),
        "circuit_identity_sha256":identity["identity_sha256"], "r1cs_sha256":identity["r1cs_sha256"],
        "phase1_radix_sha256":radix,"stage_index":index,"stage_filename":STAGE_FILE,
        "predecessor_sha256":predecessor,"stage_sha256":stage_sha,"contribution_hash":contribution,
        "source_lock_sha256":source_lock_digest(),"cargo_lock_sha256":lock_digest(),
        "phase2_git_revision":"0d286cc94af78e96d3d1184b0e38246714afa838",
        "checked_deserialization":true,"exact_eof":true,"stage_validation":validation,
        "qualified_ceremony":false,"production_release_approved":false,
        "trust_assumptions":TRUST_ASSUMPTIONS
    })
}
fn exact_fields(value: &Value, expected: &[&str]) -> bool {
    value.as_object().map(|fields| {
        fields.len() == expected.len() && expected.iter().all(|name| fields.contains_key(*name))
    }).unwrap_or(false)
}
const STAGE_RECEIPT_FIELDS: &[&str] = &[
    "schema", "status", "circuit", "ceremony_id", "circuit_identity_sha256",
    "r1cs_sha256", "phase1_radix_sha256", "stage_index", "stage_filename",
    "predecessor_sha256", "stage_sha256", "contribution_hash",
    "source_lock_sha256", "cargo_lock_sha256", "phase2_git_revision",
    "checked_deserialization", "exact_eof", "stage_validation",
    "qualified_ceremony", "production_release_approved", "trust_assumptions",
];
const STAGE_VALIDATION_FIELDS: &[&str] = &[
    "all_points_checked", "bounded_layout", "bytes", "canonical_encoding",
    "contribution_count", "cs_hash", "delta_g1_g2_consistent", "exact_eof",
    "expected_sha256", "g1_points", "g1_subgroup_basis", "g2_points",
    "g2_subgroup_checked", "ic_count", "last_record_delta_matches_vk",
    "nonzero_points", "observed_sha256", "query_counts", "same_descriptor_passes",
    "same_descriptor_stability",
];
const QUERY_COUNT_FIELDS: &[&str] = &["a", "b_g1", "b_g2", "h", "l"];
fn receipt_matches(receipt: &Value, identity: &Value, radix: &str, index: usize,
    stage_sha: &str, observed_validation: &Value) -> io::Result<()> {
    require(exact_fields(receipt, STAGE_RECEIPT_FIELDS)
        && exact_fields(&receipt["stage_validation"], STAGE_VALIDATION_FIELDS)
        && exact_fields(&receipt["stage_validation"]["query_counts"], QUERY_COUNT_FIELDS),
        "stage receipt has missing or unknown schema fields")?;
    require(receipt["schema"] == "telos-privacy-phase2-stage-v1"
        && receipt["stage_index"] == index
        && receipt["stage_sha256"] == stage_sha
        && receipt["circuit_identity_sha256"] == identity["identity_sha256"]
        && receipt["r1cs_sha256"] == identity["r1cs_sha256"]
        && receipt["phase1_radix_sha256"] == radix
        && receipt["circuit"] == identity["circuit"]
        && receipt["ceremony_id"] == ceremony_id(identity["circuit"].as_str().unwrap(),identity["identity_sha256"].as_str().unwrap(),radix)
        && receipt["stage_filename"] == STAGE_FILE
        && receipt["source_lock_sha256"] == source_lock_digest()
        && receipt["cargo_lock_sha256"] == lock_digest()
        && receipt["phase2_git_revision"] == "0d286cc94af78e96d3d1184b0e38246714afa838"
        && receipt["checked_deserialization"] == true
        && receipt["exact_eof"] == true
        && receipt["stage_validation"] == *observed_validation
        && receipt["qualified_ceremony"] == false
        && receipt["production_release_approved"] == false
        && receipt["trust_assumptions"] == json!(TRUST_ASSUMPTIONS),
        "stage receipt does not bind the checked stage")?;
    if index == 0 {
        require(receipt["status"] == "unsafe-initialization-verified"
            && receipt["predecessor_sha256"].is_null()
            && receipt["contribution_hash"].is_null(), "invalid stage zero receipt")
    } else {
        require(receipt["status"] == "single-transition-verified"
            && receipt["predecessor_sha256"].as_str().map(hex32) == Some(true)
            && receipt["contribution_hash"].as_str().map(|value| value.len() == 128
                && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) == Some(true),
            "invalid contributed stage receipt")
    }
}
fn read_entropy(fd: i32) -> io::Result<Vec<u8>> {
    require(fd >= 3, "supplemental entropy must use a private descriptor >= 3")?;
    let duplicate=unsafe { libc::dup(fd) };
    if duplicate < 0 { return Err(io::Error::last_os_error()); }
    let mut file=unsafe { File::from_raw_fd(duplicate) };
    let mut entropy=Vec::new();
    Read::by_ref(&mut file).take(MAX_ENTROPY_BYTES+1).read_to_end(&mut entropy)?;
    if !(32..=MAX_ENTROPY_BYTES as usize).contains(&entropy.len()) {
        entropy.zeroize();
        return Err(invalid("supplemental entropy must contain 32 to 4096 bytes"));
    }
    Ok(entropy)
}
struct PrivateRng(ChaChaRng);
impl Drop for PrivateRng {
    fn drop(&mut self) { self.0.reseed(&[0u32;8]); }
}
fn seeded_rng(fd: i32, identity: &str, predecessor: &str) -> io::Result<PrivateRng> {
    let mut entropy=read_entropy(fd)?;
    let mut os=[0u8;32];
    if OsRng.try_fill_bytes(&mut os).is_err() {
        entropy.zeroize(); os.zeroize();
        return Err(invalid("OS CSPRNG failed"));
    }
    let mut digest=Sha256::new();
    digest.update(b"telos-privacy-phase2-contributor-seed-v1\0");
    digest.update(hex::decode(identity).expect("validated identity"));
    digest.update(hex::decode(predecessor).expect("validated predecessor"));
    digest.update(&os);
    digest.update(&(entropy.len() as u64).to_be_bytes());
    digest.update(&entropy);
    let mut seed=[0u8;32]; seed.copy_from_slice(&digest.finalize());
    entropy.zeroize(); os.zeroize();
    let mut words=[0u32;8];
    for (word, chunk) in words.iter_mut().zip(seed.chunks_exact(4)) {
        *word=u32::from_le_bytes([chunk[0],chunk[1],chunk[2],chunk[3]]);
    }
    seed.zeroize();
    let rng=ChaChaRng::from_seed(&words);
    words.zeroize();
    Ok(PrivateRng(rng))
}

pub fn initialize(o: InitializeOpts) -> Result<(), Box<dyn std::error::Error>> {
    ensure_profile(&o.circuit,&o.expected_identity,&o.expected_radix_sha256)?;
    let (cs, identity)=compiled(&o.circuit,&o.expected_identity)?;
    let layout=layout(&cs,0)?;
    let radix_file=o.radix.join(format!("phase1radix2m{}",layout.domain.trailing_zeros()));
    let mut radix=ceremony_input::snapshot_radix(&radix_file,&o.expected_radix_sha256,layout)?;
    let circuit=BellmanCS::<Bn256,BuildCS<Fr>>::new(cs.clone());
    let params=MPCParameters::new(circuit,true,&radix.directory()?)?;
    radix.recheck()?;
    let circuit=BellmanCS::<Bn256,BuildCS<Fr>>::new(cs);
    require(params.verify(circuit,true,&radix.directory()?).map_err(|_| invalid("stage zero full circuit verification failed"))?.is_empty(),
        "stage zero unexpectedly contains contributions")?;
    radix.recheck()?;
    let stage=StageDirectory::new(&o.stage_directory)?;
    stage.write_params(&params)?;
    let (serialized,validation)=ceremony_input::load_transcript(&stage.path(STAGE_FILE),
        &digest_file(&stage.path(STAGE_FILE))?,layout)?;
    require(serialized==params,"serialized stage zero differs from fully verified initialization")?;
    let stage_sha=validation["observed_sha256"].as_str().ok_or_else(||invalid("missing stage digest"))?;
    let result=receipt(&identity,&o.expected_radix_sha256,0,None,stage_sha,None,&validation);
    stage.write_json(RECEIPT_FILE,&result)?;
    println!("Unsafe stage zero initialized and circuit-verified; no contribution or qualified ceremony exists.");
    Ok(())
}

fn digest_file(path: &Path) -> io::Result<String> {
    let mut file=File::open(path)?;
    let mut hash=Sha256::new();
    let mut buf=[0u8;1024*1024];
    loop { let n=file.read(&mut buf)?; if n==0 { break; } hash.update(&buf[..n]); }
    Ok(hex::encode(hash.finalize()))
}

pub fn contribute(o: ContributeOpts) -> Result<(), Box<dyn std::error::Error>> {
    ensure_profile(&o.circuit,&o.expected_identity,&o.expected_radix_sha256)?;
    require(hex32(&o.expected_before_sha256),"predecessor digest must be lowercase SHA256")?;
    require(o.stage_index >= 1 && o.stage_index <= ceremony_input::MAX_CONTRIBUTIONS,
        "stage index outside reviewed bound")?;
    let (cs,identity)=compiled(&o.circuit,&o.expected_identity)?;
    let before_layout=layout(&cs,o.stage_index-1)?;
    let (before,before_validation)=ceremony_input::load_transcript(&o.before,&o.expected_before_sha256,before_layout)?;
    let old_receipt=ceremony_input::read_small_json(&o.before_receipt,MAX_RECEIPT_BYTES)?;
    receipt_matches(&old_receipt,&identity,&o.expected_radix_sha256,o.stage_index-1,
        &o.expected_before_sha256,&before_validation)?;
    if o.stage_index == 1 {
        require(old_receipt["status"] == "unsafe-initialization-verified"
            && old_receipt["contribution_hash"].is_null(), "first stage must follow verified initialization")?;
    } else {
        require(old_receipt["status"] == "single-transition-verified", "predecessor lacks verified transition receipt")?;
    }
    let mut rng=seeded_rng(o.entropy_fd,&o.expected_identity,&o.expected_before_sha256)?;
    let mut after=before.clone();
    let claimed=after.contribute(&mut rng.0,&0u32);
    drop(rng); // Best effort even on unwind. Copies and OS memory are outside this guarantee.
    let verified=verify_contribution(&before,&after).map_err(|_|invalid("contribution transition verification failed"))?;
    require(claimed==verified,"contributor hash differs from transition verifier")?;
    let after_layout=layout(&cs,o.stage_index)?;
    let stage=StageDirectory::new(&o.stage_directory)?;
    stage.write_params(&after)?;
    let stage_path=stage.path(STAGE_FILE);
    let stage_digest=digest_file(&stage_path)?;
    let (observed,validation)=ceremony_input::load_transcript(&stage_path,&stage_digest,after_layout)?;
    require(observed==after,"serialized successor differs from verified in-memory contribution")?;
    require(verify_contribution(&before,&observed).map_err(|_|invalid("serialized transition verification failed"))?==claimed,
        "serialized contribution hash differs")?;
    let contribution_hex=hex::encode(claimed);
    let result=receipt(&identity,&o.expected_radix_sha256,o.stage_index,
        Some(&o.expected_before_sha256),&stage_digest,Some(&contribution_hex),&validation);
    let statement=json!({
        "schema":"telos-privacy-phase2-participant-statement-v1",
        "status":"unsigned-needs-independent-signature-and-entropy-destruction-attestation",
        "circuit":result["circuit"],
        "ceremony_id":result["ceremony_id"],"circuit_identity_sha256":result["circuit_identity_sha256"],
        "r1cs_sha256":result["r1cs_sha256"],"phase1_radix_sha256":result["phase1_radix_sha256"],
        "stage_index":o.stage_index,"predecessor_sha256":o.expected_before_sha256,
        "stage_sha256":stage_digest,"contribution_hash":contribution_hex,
        "stage_receipt_filename":RECEIPT_FILE,
        "participant_identity":"TO_BE_FILLED_AND_SIGNED_EXTERNALLY",
        "entropy_destruction_attestation":"TO_BE_ATTESTED_EXTERNALLY"
    });
    stage.write_json(STATEMENT_FILE,&statement)?;
    stage.write_json(RECEIPT_FILE,&result)?;
    println!("One contribution transition verified and staged; independent signature and full ceremony verification remain required.");
    Ok(())
}

pub fn verify_transition(o: VerifyTransitionOpts) -> Result<(), Box<dyn std::error::Error>> {
    ensure_profile(&o.circuit,&o.expected_identity,&o.expected_radix_sha256)?;
    require(hex32(&o.expected_before_sha256) && hex32(&o.expected_after_sha256),
        "stage digests must be lowercase SHA256")?;
    require(o.stage_index>=1 && o.stage_index<=ceremony_input::MAX_CONTRIBUTIONS,
        "stage index outside reviewed bound")?;
    let (cs,identity)=compiled(&o.circuit,&o.expected_identity)?;
    let (before,_)=ceremony_input::load_transcript(&o.before,&o.expected_before_sha256,layout(&cs,o.stage_index-1)?)?;
    let (after,after_validation)=ceremony_input::load_transcript(&o.after,&o.expected_after_sha256,layout(&cs,o.stage_index)?)?;
    let hash=hex::encode(verify_contribution(&before,&after).map_err(|_|invalid("stage transition invalid"))?);
    let stage_receipt=ceremony_input::read_small_json(&o.after_receipt,MAX_RECEIPT_BYTES)?;
    receipt_matches(&stage_receipt,&identity,&o.expected_radix_sha256,o.stage_index,
        &o.expected_after_sha256,&after_validation)?;
    require(stage_receipt["status"]=="single-transition-verified"
        && stage_receipt["predecessor_sha256"]==o.expected_before_sha256
        && stage_receipt["contribution_hash"]==hash, "receipt differs from verified transition")?;
    println!("Stage transition and receipt agree with independently supplied byte anchors; participant identity is not authenticated.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn validation_fixture(digest: &str) -> Value {
        json!({
            "all_points_checked":true,"bounded_layout":true,"bytes":1024,
            "canonical_encoding":true,"contribution_count":1,"cs_hash":"00".repeat(64),
            "delta_g1_g2_consistent":true,"exact_eof":true,"expected_sha256":digest,
            "g1_points":10,"g1_subgroup_basis":"BN254 G1 cofactor one; checked curve membership",
            "g2_points":5,"g2_subgroup_checked":true,"ic_count":6,
            "last_record_delta_matches_vk":true,"nonzero_points":true,
            "observed_sha256":digest,"query_counts":{"a":2,"b_g1":2,"b_g2":2,"h":1,"l":1},
            "same_descriptor_passes":2,"same_descriptor_stability":true
        })
    }
    #[test] fn stage_id_binds_circuit_identity_and_radix() {
        let a="11".repeat(32); let b="22".repeat(32); let c="33".repeat(32);
        assert_ne!(ceremony_id("transfer",&a,&b),ceremony_id("transfer",&a,&c));
        assert_ne!(ceremony_id("transfer",&a,&b),ceremony_id("transfer",&b,&b));
        assert_ne!(ceremony_id("transfer",&a,&b),ceremony_id("tree_update",&a,&b));
        assert!(ensure_profile("transfer",&a,&b).is_ok());
        assert!(ensure_profile("tree_update",&a,&b).is_ok());
        assert!(ensure_profile("delegated_deposit",&a,&b).is_err());
    }
    #[test] fn entropy_fd_is_restricted() {
        assert!(read_entropy(0).is_err()); assert!(read_entropy(1).is_err()); assert!(read_entropy(2).is_err());
        assert!(read_entropy(500000).is_err());
    }
    #[test] fn entropy_pipe_is_bounded_and_not_returned_in_a_receipt() {
        let mut descriptors=[-1,-1];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) },0);
        assert!(descriptors[0]>=3);
        let marker=[0xA5u8;32];
        assert_eq!(unsafe { libc::write(descriptors[1],marker.as_ptr().cast(),marker.len()) },32);
        assert_eq!(unsafe { libc::close(descriptors[1]) },0);
        let mut entropy=read_entropy(descriptors[0]).unwrap();
        assert_eq!(entropy,marker);
        entropy.zeroize();
        assert_eq!(unsafe { libc::close(descriptors[0]) },0);
    }
    #[test] fn stage_directory_never_replaces_an_existing_stage() {
        let mut random=[0u8;16]; OsRng.try_fill_bytes(&mut random).unwrap();
        let path=std::env::temp_dir().canonicalize().unwrap().join(format!("telos-stage-exclusive-test-{}",hex::encode(random)));
        let stage=StageDirectory::new(&path).unwrap();
        let mut file=stage.create("probe").unwrap(); file.write_all(b"test").unwrap(); file.sync_all().unwrap();
        assert!(stage.create("probe").is_err());
        assert!(StageDirectory::new(&path).is_err());
        drop(file); drop(stage);
        std::fs::remove_file(path.join("probe")).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
    #[test] fn receipt_binding_rejects_wrong_stage() {
        let identity=json!({"circuit":"transfer","identity_sha256":"11".repeat(32),"r1cs_sha256":"22".repeat(32)});
        let receipt=receipt(&identity,&"33".repeat(32),1,Some(&"44".repeat(32)),&"55".repeat(32),Some(&"66".repeat(64)),&validation_fixture(&"55".repeat(32)));
        let validation=validation_fixture(&"55".repeat(32));
        assert!(receipt_matches(&receipt,&identity,&"33".repeat(32),1,&"55".repeat(32),&validation).is_ok());
        assert!(receipt_matches(&receipt,&identity,&"33".repeat(32),2,&"55".repeat(32),&validation).is_err());
        let other=json!({"circuit":"tree_update","identity_sha256":"11".repeat(32),"r1cs_sha256":"22".repeat(32)});
        assert!(receipt_matches(&receipt,&other,&"33".repeat(32),1,&"55".repeat(32),&validation).is_err());
    }
    #[test] fn receipt_schema_rejects_unknown_or_missing_fields_at_every_object_level() {
        let identity=json!({"circuit":"transfer","identity_sha256":"11".repeat(32),"r1cs_sha256":"22".repeat(32)});
        let radix="33".repeat(32); let stage="55".repeat(32);
        let valid=receipt(&identity,&radix,1,Some(&"44".repeat(32)),&stage,
            Some(&"66".repeat(64)),&validation_fixture(&stage));
        let validation=validation_fixture(&stage);
        assert!(receipt_matches(&valid,&identity,&radix,1,&stage,&validation).is_ok());
        let mut random=[0u8;16]; OsRng.try_fill_bytes(&mut random).unwrap();
        let path=std::env::temp_dir().canonicalize().unwrap().join(
            format!("telos-receipt-roundtrip-{}",hex::encode(random)));
        let directory=StageDirectory::new(&path).unwrap();
        directory.write_json(RECEIPT_FILE,&valid).unwrap();
        let reloaded=ceremony_input::read_small_json(&directory.path(RECEIPT_FILE),MAX_RECEIPT_BYTES).unwrap();
        assert_eq!(reloaded,valid);
        assert!(receipt_matches(&reloaded,&identity,&radix,1,&stage,&validation).is_ok());
        drop(directory);
        std::fs::remove_file(path.join(RECEIPT_FILE)).unwrap();
        std::fs::remove_dir(path).unwrap();
        let mut top=valid.clone(); top["unreviewed"] = json!(true);
        assert!(receipt_matches(&top,&identity,&radix,1,&stage,&validation).is_err());
        let mut missing=valid.clone(); missing.as_object_mut().unwrap().remove("trust_assumptions");
        assert!(receipt_matches(&missing,&identity,&radix,1,&stage,&validation).is_err());
        let mut nested=valid.clone(); nested["stage_validation"]["unreviewed"] = json!(true);
        assert!(receipt_matches(&nested,&identity,&radix,1,&stage,&validation).is_err());
        let mut query=valid; query["stage_validation"]["query_counts"]["unreviewed"] = json!(1);
        assert!(receipt_matches(&query,&identity,&radix,1,&stage,&validation).is_err());
    }
    #[test] fn receipt_values_must_match_fresh_stage_validation() {
        let identity=json!({"circuit":"transfer","identity_sha256":"11".repeat(32),"r1cs_sha256":"22".repeat(32)});
        let radix="33".repeat(32); let stage="55".repeat(32);
        let validation=validation_fixture(&stage);
        let original=receipt(&identity,&radix,1,Some(&"44".repeat(32)),&stage,
            Some(&"66".repeat(64)),&validation);
        assert!(receipt_matches(&original,&identity,&radix,1,&stage,&validation).is_ok());
        for field in ["checked_deserialization", "exact_eof"] {
            let mut tampered=original.clone(); tampered[field]=json!(false);
            assert!(receipt_matches(&tampered,&identity,&radix,1,&stage,&validation).is_err(), "{}", field);
        }
        for (field, changed) in [
            ("observed_sha256", json!("77".repeat(32))),
            ("contribution_count", json!(0)),
            ("g2_subgroup_checked", json!(false)),
        ] {
            let mut tampered=original.clone(); tampered["stage_validation"][field]=changed;
            assert!(receipt_matches(&tampered,&identity,&radix,1,&stage,&validation).is_err(), "{}", field);
        }
        for (field, changed) in [
            ("status", json!("unsafe-initialization-verified")),
            ("predecessor_sha256", json!(null)),
            ("contribution_hash", json!("bad")),
            ("trust_assumptions", json!([])),
        ] {
            let mut tampered=original.clone(); tampered[field]=changed;
            assert!(receipt_matches(&tampered,&identity,&radix,1,&stage,&validation).is_err(), "{}", field);
        }
    }
}
