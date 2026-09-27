//! Read-only circuit-bound phase2 verification with explicit external trust anchors.
use super::circuit_identity;
use super::ceremony_input::{self, Layout};
use fawkes_crypto::{backend::bellman_groth16::{BellmanCS, Parameters, engines::Bn256}, circuit::cs::BuildCS, engines::bn256::Fr};
use fawkes_crypto::BorshSerialize;
use libzeropool_zkbob::clap::Clap;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, path::{Path, PathBuf}};

#[derive(Clap)]
pub struct VerifyCeremonyOpts {
    #[clap(long)] circuit: String,
    #[clap(long)] params: PathBuf,
    /// Independently approved SHA256 of the complete MPC transcript.
    #[clap(long)] expected_params_sha256: String,
    #[clap(long)] radix: PathBuf,
    #[clap(long)] expected_radix_sha256: String,
    #[clap(long)] expected_identity: String,
    /// JSON array of independently recorded phase2 contribution hashes, in order (at least two).
    #[clap(long)] expected_contributions: PathBuf,
    /// New receipt file; must not exist. No receipt is emitted on verification failure.
    #[clap(long)] receipt: PathBuf,
    /// Optionally derive final parameters, VK and verifier into a NEW directory after full verification.
    #[clap(long)] finalize_directory: Option<PathBuf>,
}
fn digest_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 1024*1024];
    loop { let len=file.read(&mut buffer)?; if len==0 {break;} hash.update(&buffer[..len]); }
    Ok(hex::encode(hash.finalize()))
}
fn valid_hex(text: &str, bytes: usize) -> bool { text.len()==bytes*2 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

pub fn run(o: VerifyCeremonyOpts) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(o.circuit.as_str(), "transfer" | "tree_update") {
        return Err("this prototype verifies only its source-locked transfer or tree_update relation".into());
    }
    if !(cfg!(feature="cli_libzeropool_setup") && cfg!(feature="in3out127"))
        || cfg!(feature="in1out127") || cfg!(feature="in7ount127") || cfg!(feature="in15out127") {
        return Err("ceremony verification requires only cli_libzeropool_setup and in3out127".into());
    }
    if !valid_hex(&o.expected_identity,32) || !valid_hex(&o.expected_radix_sha256,32)
        || !ceremony_input::valid_sha256(&o.expected_params_sha256) {
        return Err("expected identity/radix/transcript hash must be lowercase SHA256".into());
    }
    if o.receipt.exists() { return Err("receipt path already exists".into()); }
    let (expected, contribution_anchors_sha256) = ceremony_input::read_anchors(&o.expected_contributions)?;
    let (cs, metadata) = circuit_identity::build(&o.circuit)?;
    let identity = circuit_identity::describe(&cs.borrow(),metadata,io::sink())?;
    if identity["identity_sha256"]!=o.expected_identity { return Err("compiled circuit identity does not match approval".into()); }
    // Bounds derive from the same circuit that the phase2 verifier synthesizes.
    // The assembly appends one density row for every input including one.
    let layout = {
        let cs = cs.borrow();
        Layout::new(cs.num_input, cs.num_aux, cs.gates.len(), expected.len())?
    };
    let exponent = layout.domain.trailing_zeros();
    let radix_name = format!("phase1radix2m{}",exponent);
    let radix_path = o.radix.join(&radix_name);
    let (params, transcript_validation) =
        ceremony_input::load_transcript(&o.params, &o.expected_params_sha256, layout)?;
    let mut radix = ceremony_input::snapshot_radix(&radix_path, &o.expected_radix_sha256, layout)?;
    radix.recheck()?;
    let circuit = BellmanCS::<Bn256,BuildCS<Fr>>::new(cs.clone());
    // The pinned library reopens a filename and uses unchecked radix decoding.
    // Only the previously point-checked private snapshot is supplied to it.
    let contributions = params.verify(circuit,true,&radix.directory()?).map_err(|_| "full phase2 verification failed")?;
    let actual: Vec<String> = contributions.iter().map(hex::encode).collect();
    if actual!=expected { return Err("verified contribution hashes differ from independently recorded list".into()); }
    radix.recheck()?;
    radix.validation["snapshot_rechecked_after_verification"] = json!(true);
    let params_hash = &o.expected_params_sha256;
    let radix_hash = &o.expected_radix_sha256;
    let mut vk = Vec::new(); params.get_params().vk.write(&mut vk)?;
    let receipt = json!({
        "schema":"telos-privacy-ceremony-verification-v5-two-circuit-prototype", "status":"cryptographic-verification-passed",
        "circuit":o.circuit, "circuit_identity_sha256":identity["identity_sha256"], "r1cs_sha256":identity["r1cs_sha256"],
        "source_lock_sha256":hex::encode(Sha256::digest(include_bytes!("../../formal/ceremony-source-lock.json"))),
        "cargo_lock_sha256":hex::encode(Sha256::digest(include_bytes!("../../Cargo.lock"))),
        "mpc_params_sha256":params_hash,
        "phase1_radix":{"filename":radix_name,"sha256":radix_hash},
        "phase2_source_kind":"Cargo.lock pinned upstream git revision",
        "fawkes_git_revision":"6ba6a4538f13864ad64bdff8d71512c2ee7356cf",
        "phase2_baseline_git_revision":"0d286cc94af78e96d3d1184b0e38246714afa838",
        "contribution_hashes":actual, "groth16_vk_binary_sha256":hex::encode(Sha256::digest(vk)),
        "contribution_anchor_file_sha256":contribution_anchors_sha256,
        "checked_point_deserialization":true, "circuit_bound_full_verification":true,
        "validation":{
            "schema":"telos-privacy-ceremony-input-validation-v1",
            "transcript":transcript_validation,"radix":radix.validation
        },
        "loader_source_sha256":{
            "src/setup/ceremony_input.rs":hex::encode(Sha256::digest(include_bytes!("ceremony_input.rs"))),
            "src/setup/ceremony_verify.rs":hex::encode(Sha256::digest(include_bytes!("ceremony_verify.rs")))
        },
        "phase1_ceremony_verified":false,"production_reuse_approved":false,
        "trust_assumptions":["independently approved phase1 radix and verification transcript", "at least one independent honest phase2 participant destroyed secret entropy", "pinned compiler and cryptographic implementation"]
    });
    if let Some(directory)=o.finalize_directory {
        // Build prover metadata from this exact circuit, never from an arbitrary meta file.
        // The MPC transcript remains immutable and is distinct from finalized parameters.
        std::fs::create_dir(&directory)?;
        let cs=cs.borrow();
        let mut compressed=Vec::new();
        {
            let mut compressor=brotli::CompressorWriter::new(&mut compressed,4096,9,22);
            for g in &cs.gates { compressor.write_all(&g.try_to_vec()?)?; }
            compressor.flush()?;
        }
        let final_params=Parameters::<Bn256>(params.get_params().clone(),cs.gates.len() as u32,compressed,cs.const_tracker.clone());
        let parameters_path=directory.join("parameters.bin");
        let mut final_file=OpenOptions::new().create_new(true).write(true).open(&parameters_path)?;
        final_params.write(&mut final_file)?; final_file.sync_all()?;
        let vk=final_params.get_vk();
        let vk_bytes=serde_json::to_vec_pretty(&vk)?;
        let contract_name=match o.circuit.as_str() {"transfer"=>"TransferVerifier","tree_update"=>"TreeUpdateVerifier",_=>"DelegatedDepositVerifier"};
        let verifier=super::evm_verifier::generate_sol_data(&vk,contract_name.to_string());
        let write_new=|name:&str,bytes:&[u8]|->io::Result<()> {
            let mut file=OpenOptions::new().create_new(true).write(true).open(directory.join(name))?;
            file.write_all(bytes)?;file.sync_all()
        };
        write_new("verification_key.json",&vk_bytes)?;
        write_new("Verifier.sol",verifier.as_bytes())?;
        let derivation=json!({
            "schema":"telos-privacy-artifact-derivation-v4-two-circuit-prototype",
            "status":"derived-awaiting-independent-solidity-compilation",
            "circuit":o.circuit, "circuitIdentitySha256":identity["identity_sha256"],
            "mpcTranscriptSha256":params_hash, "parametersSha256":digest_file(&parameters_path)?,
            "verificationKeySha256":hex::encode(Sha256::digest(&vk_bytes)),
            "verifierSourceSha256":hex::encode(Sha256::digest(verifier.as_bytes())),
            "sourceLockSha256":receipt["source_lock_sha256"],
            "phase2BaselineGitRevision":receipt["phase2_baseline_git_revision"],
            "phase2SourceKind":receipt["phase2_source_kind"],
            "fawkesGitRevision":receipt["fawkes_git_revision"],
            "requiredNextStep":"Independently regenerate verifier from VK and compile with approved solc settings; bind runtime hash and compiler identity in release gate."
        });
        let mut derivation_bytes=serde_json::to_vec_pretty(&derivation)?;
        derivation_bytes.push(b'\n');
        write_new("derivation-receipt.json",&derivation_bytes)?;
    }
    let mut output=OpenOptions::new().create_new(true).write(true).open(o.receipt)?;
    serde_json::to_writer_pretty(&mut output,&receipt)?; output.write_all(b"\n")?; output.sync_all()?;
    println!("Full phase2 verification passed; receipt written.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn trust_anchor_hashes_have_exact_encoding() {
        assert!(valid_hex(&"ab".repeat(32),32));
        assert!(!valid_hex(&"AB".repeat(32),32));
        assert!(!valid_hex(&"ab".repeat(31),32));
    }
}
