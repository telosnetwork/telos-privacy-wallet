//! Strict loading of public ceremony inputs. This is not a phase1 verifier.
//!
//! The legacy phase2 verifier reopens its radix filename and uses unchecked point
//! decoding. It receives only a private, fully checked copy. The executing OS and
//! user account remain trusted: mode bits do not isolate malicious same-UID code.
use bellman::pairing::{
    bn256::{G1Affine, G1Uncompressed, G2Affine, G2Uncompressed},
    CurveAffine, EncodedPoint, RawEncodable,
};
use fawkes_crypto_phase2::{parameters::MPCParameters, utils::same_ratio};
use rand::{rngs::OsRng, RngCore};
use serde::{de::{self, MapAccess, SeqAccess, Visitor}, Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    io::{AsRawFd, FromRawFd},
};

pub const MAX_CONTRIBUTIONS: usize = 4096;
const MAX_ANCHOR_BYTES: u64 = 1024 * 1024;
const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
// Covers the three current in3out127 circuits. Larger domains need a deliberate
// resource/format review; the legacy library's much larger ceiling is not used.
const MAX_DOMAIN: u64 = 1 << 21;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(invalid(message)) }
}
pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64, inode: u64, bytes: u64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}
#[cfg(unix)]
fn identity(m: &Metadata) -> Identity {
    Identity { device: m.dev(), inode: m.ino(), bytes: m.len(),
        mtime: m.mtime(), mtime_ns: m.mtime_nsec(), ctime: m.ctime(), ctime_ns: m.ctime_nsec() }
}
#[cfg(not(unix))]
fn identity(_: &Metadata) -> Identity { unreachable!("strict opening is unavailable on this platform") }

// Walk from an open root directory using O_NOFOLLOW on every component. A
// lstat-then-open check alone would permit a parent-symlink race. O_NONBLOCK
// prevents a named pipe from blocking before the regular-file check.
#[cfg(unix)]
fn open_path(path: &Path, directory: bool) -> io::Result<File> {
    use std::ffi::CString;
    let absolute = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    let mut names = Vec::new();
    for part in absolute.components() {
        match part {
            Component::RootDir | Component::CurDir => {},
            Component::Normal(name) => names.push(CString::new(name.as_bytes()).map_err(|_| invalid("NUL in input path"))?),
            _ => return Err(invalid("parent components are not permitted in input paths")),
        }
    }
    require(!names.is_empty(), "input path must name a file or private directory")?;
    let mut parent = OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open("/")?;
    for (i, name) in names.iter().enumerate() {
        let is_directory = i + 1 < names.len() || directory;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
            | if is_directory { libc::O_DIRECTORY } else { 0 };
        // SAFETY: name is NUL-terminated, parent owns a live directory descriptor,
        // and the returned descriptor is transferred into one owning File.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        parent = unsafe { File::from_raw_fd(fd) };
    }
    let m = parent.metadata()?;
    require(if directory { m.is_dir() } else { m.is_file() }, "input is not an ordinary file/directory")?;
    Ok(parent)
}
#[cfg(unix)]
pub(super) fn open_checked_directory(path: &Path) -> io::Result<File> { open_path(path, true) }
// `serde_json::Value` silently keeps the last occurrence of an object key.
// Receipts cross a participant/coordinator trust boundary, so reject duplicate
// keys recursively before any binding check can interpret an ambiguous object.
struct NoDuplicateValue(Value);
impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Value;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> { Ok(Value::Bool(value)) }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> { Ok(Value::Number(value.into())) }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> { Ok(Value::Number(value.into())) }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
                serde_json::Number::from_f64(value).map(Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> { Ok(Value::String(value.to_owned())) }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> { Ok(Value::String(value)) }
            fn visit_none<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
            fn visit_unit<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
            fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
                NoDuplicateValue::deserialize(deserializer).map(|value| value.0)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<NoDuplicateValue>()? {
                    values.push(value.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, NoDuplicateValue>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
                    }
                    values.insert(key, value.0);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(StrictVisitor).map(Self)
    }
}
#[cfg(unix)]
pub(super) fn read_small_json(path: &Path, maximum: u64) -> io::Result<Value> {
    let mut file = open_path(path, false)?;
    let before = identity(&file.metadata()?);
    require(before.bytes > 0 && before.bytes <= maximum, "JSON input exceeds reviewed bound")?;
    let mut bytes = Vec::new();
    let mut reader = CheckedReader::new(&mut file, before.bytes, None);
    reader.read_to_end(&mut bytes)?;
    reader.finish(None)?;
    require(identity(&file.metadata()?) == before, "JSON input changed while reading")?;
    serde_json::from_slice::<NoDuplicateValue>(&bytes)
        .map(|value| value.0).map_err(|e| invalid(e.to_string()))
}
#[cfg(not(unix))]
fn open_path(_: &Path, _: bool) -> io::Result<File> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "strict ceremony input loading requires Unix descriptor semantics"))
}

// Hash (and optionally copy) exactly the bytes consumed by the parser. A second
// pass can seek the SAME descriptor; no path-based reopen is used for transcripts.
struct CheckedReader<'a> {
    reader: BufReader<&'a mut File>, copy: Option<&'a mut File>,
    hash: Sha256, bytes: u64, limit: u64,
}
impl<'a> CheckedReader<'a> {
    fn new(file: &'a mut File, limit: u64, copy: Option<&'a mut File>) -> Self {
        Self { reader: BufReader::with_capacity(1024 * 1024, file), copy,
            hash: Sha256::new(), bytes: 0, limit }
    }
    fn finish(mut self, expected: Option<&str>) -> io::Result<String> {
        let mut extra = [0; 1];
        require(self.read(&mut extra)? == 0, "trailing bytes after ceremony input")?;
        require(self.bytes == self.limit, "ceremony input length changed or is truncated")?;
        let hash = hex::encode(self.hash.finalize());
        if let Some(expected) = expected { require(hash == expected, "ceremony input SHA256 does not match expected digest")?; }
        Ok(hash)
    }
}
impl Read for CheckedReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(out)?;
        self.bytes = self.bytes.checked_add(n as u64).ok_or_else(|| invalid("byte count overflow"))?;
        require(self.bytes <= self.limit, "ceremony input exceeds its bounded length")?;
        if let Some(copy) = &mut self.copy { copy.write_all(&out[..n])?; }
        self.hash.update(&out[..n]);
        Ok(n)
    }
}
fn hash_descriptor(file: &mut File, expected_identity: Identity, expected_hash: &str) -> io::Result<()> {
    require(identity(&file.metadata()?) == expected_identity, "input metadata changed before read")?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = CheckedReader::new(file, expected_identity.bytes, None);
    io::copy(&mut reader, &mut io::sink())?;
    reader.finish(Some(expected_hash))?;
    require(identity(&file.metadata()?) == expected_identity, "input metadata changed during read")
}

pub fn read_anchors(path: &Path) -> io::Result<(Vec<String>, String)> {
    let mut file = open_path(path, false)?;
    let before = identity(&file.metadata()?);
    require(before.bytes > 0 && before.bytes <= MAX_ANCHOR_BYTES, "contribution anchor file exceeds bound")?;
    let mut bytes = Vec::new();
    let mut reader = CheckedReader::new(&mut file, before.bytes, None);
    reader.read_to_end(&mut bytes)?;
    let digest = reader.finish(None)?;
    require(identity(&file.metadata()?) == before, "contribution anchor file changed during read")?;
    let anchors: Vec<String> = serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
    require((2..=MAX_CONTRIBUTIONS).contains(&anchors.len()), "between 2 and 4096 independently recorded contribution hashes are required")?;
    require(anchors.iter().all(|v| v.len() == 128 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))), "invalid contribution hash encoding")?;
    let unique: std::collections::HashSet<_> = anchors.iter().collect();
    require(unique.len() == anchors.len(), "duplicate contribution receipts")?;
    Ok((anchors, digest))
}

#[derive(Clone, Copy, Debug)]
pub struct Layout {
    inputs: u64, aux: u64, variables: u64, pub domain: u64, contributions: u64,
}
impl Layout {
    pub fn new(inputs: usize, aux: usize, gates: usize, contributions: usize) -> io::Result<Self> {
        require((2..=MAX_CONTRIBUTIONS).contains(&contributions), "unsupported contribution count")?;
        Self::stage(inputs, aux, gates, contributions)
    }
    /// The contributor inspects stage zero and each single-successor stage.
    /// The final verifier still requires at least two independent anchors.
    pub fn stage(inputs: usize, aux: usize, gates: usize, contributions: usize) -> io::Result<Self> {
        require(contributions <= MAX_CONTRIBUTIONS, "unsupported stage contribution count")?;
        require(inputs > 0 && inputs <= 64 && aux > 0 && aux <= (1 << 22), "circuit dimensions exceed loader bounds")?;
        let constraints = gates.checked_add(inputs).ok_or_else(|| invalid("constraint count overflow"))?;
        let domain = constraints.checked_next_power_of_two().ok_or_else(|| invalid("domain overflow"))? as u64;
        require(domain >= 2 && domain <= MAX_DOMAIN, "circuit domain exceeds reviewed loader bound")?;
        Ok(Self { inputs: inputs as u64, aux: aux as u64, variables: (inputs + aux) as u64,
            domain, contributions: contributions as u64 })
    }
    pub fn radix_bytes(&self) -> u64 { 192 + 384 * self.domain }
    fn max_transcript_bytes(&self) -> u64 {
        668 + 64 * (self.inputs + self.domain - 1 + self.aux + 4 * self.variables) + 384 * self.contributions
    }
}

#[derive(Default)]
struct Points { g1: u64, g2: u64 }
impl Points {
    fn g1(&mut self, reader: &mut impl Read) -> io::Result<G1Affine> {
        let mut encoded = G1Uncompressed::empty(); reader.read_exact(encoded.as_mut())?;
        let point = encoded.into_affine().map_err(|e| invalid(format!("G1 point {}: {e:?}", self.g1)))?;
        require(!point.is_zero(), "G1 infinity is not permitted")?;
        require(point.into_uncompressed().as_ref() == encoded.as_ref(), "noncanonical G1 encoding")?;
        // BN254 G1 has cofactor one. The checked decoder verifies the curve.
        self.g1 += 1;
        Ok(point)
    }
    fn g2(&mut self, reader: &mut impl Read) -> io::Result<G2Affine> {
        let mut encoded = G2Uncompressed::empty(); reader.read_exact(encoded.as_mut())?;
        let point = encoded.into_affine().map_err(|e| invalid(format!("G2 point {}: {e:?}", self.g2)))?;
        require(!point.is_zero(), "G2 infinity is not permitted")?;
        require(point.into_uncompressed().as_ref() == encoded.as_ref(), "noncanonical G2 encoding")?;
        // This pinned into_affine() only checks the curve. The checked RAW route
        // additionally multiplies by Fr::char(), and must return the SAME point.
        let raw = point.into_raw_uncompressed_le();
        let checked = G2Affine::from_raw_uncompressed_le(&raw, false)
            .map_err(|e| invalid(format!("G2 subgroup at point {}: {e:?}", self.g2)))?;
        require(checked == point && !checked.is_zero(), "G2 subgroup roundtrip differs")?;
        require(checked.into_raw_uncompressed_le().as_ref() == raw.as_ref(), "G2 raw encoding roundtrip differs")?;
        self.g2 += 1;
        Ok(point)
    }
    fn report(&self) -> Value {
        json!({"all_points_checked":true,"g2_subgroup_checked":true,
            "canonical_encoding":true,"nonzero_points":true,"bounded_layout":true,
            "exact_eof":true,"same_descriptor_stability":true,
            "g1_points":self.g1,"g2_points":self.g2,
            "g1_subgroup_basis":"BN254 G1 cofactor one; checked curve membership"})
    }
}
fn count(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 4]; reader.read_exact(&mut bytes)?; Ok(u32::from_be_bytes(bytes) as u64)
}
fn scan_transcript(reader: &mut impl Read, layout: Layout) -> io::Result<Value> {
    let mut points = Points::default();
    points.g1(reader)?; points.g1(reader)?;
    points.g2(reader)?; points.g2(reader)?;
    let delta = points.g1(reader)?; points.g2(reader)?;
    require(count(reader)? == layout.inputs, "IC length differs from compiled circuit")?;
    for _ in 0..layout.inputs { points.g1(reader)?; }
    let mut counts = serde_json::Map::new();
    let mut b_g1 = 0;
    for name in ["h", "l", "a", "b_g1", "b_g2"] {
        let n = count(reader)?;
        let valid = match name { "h" => n == layout.domain - 1, "l" => n == layout.aux,
            _ => n > 0 && n <= layout.variables };
        require(valid, "query count outside compiled circuit bounds")?;
        if name == "b_g1" { b_g1 = n; }
        if name == "b_g2" { require(n == b_g1, "B-G1 and B-G2 query counts differ")?; }
        counts.insert(name.to_owned(), json!(n));
        for _ in 0..n { if name == "b_g2" { points.g2(reader)?; } else { points.g1(reader)?; } }
    }
    let mut cs_hash = [0; 64]; reader.read_exact(&mut cs_hash)?;
    require(count(reader)? == layout.contributions, "contribution count differs from independent anchor count")?;
    for i in 0..layout.contributions {
        let after = points.g1(reader)?;
        if i + 1 == layout.contributions { require(after == delta, "last contribution delta differs from VK delta G1")?; }
        points.g1(reader)?; points.g1(reader)?; points.g2(reader)?;
        let mut transcript_hash = [0; 64]; reader.read_exact(&mut transcript_hash)?;
    }
    let mut report = points.report();
    report["query_counts"] = json!(counts);
    report["ic_count"] = json!(layout.inputs);
    report["contribution_count"] = json!(layout.contributions);
    report["cs_hash"] = json!(hex::encode(cs_hash));
    report["last_record_delta_matches_vk"] = json!(true);
    Ok(report)
}

pub fn load_transcript(path: &Path, expected: &str, layout: Layout) -> io::Result<(MPCParameters, Value)> {
    require(valid_sha256(expected), "invalid expected transcript SHA256")?;
    let mut file = open_path(path, false)?;
    let before = identity(&file.metadata()?);
    require(before.bytes >= 668 && before.bytes <= layout.max_transcript_bytes()
        && before.bytes <= MAX_INPUT_BYTES, "transcript size outside reviewed bound")?;
    let mut reader = CheckedReader::new(&mut file, before.bytes, None);
    let mut report = scan_transcript(&mut reader, layout)?;
    reader.finish(Some(expected))?;
    require(identity(&file.metadata()?) == before, "transcript changed during point validation")?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = CheckedReader::new(&mut file, before.bytes, None);
    let params = MPCParameters::read(&mut reader, true, true)?;
    let hash = reader.finish(Some(expected))?;
    require(identity(&file.metadata()?) == before, "transcript changed during library decoding")?;
    let vk = &params.get_params().vk;
    require(same_ratio((G1Affine::one(), vk.delta_g1), (G2Affine::one(), vk.delta_g2)),
        "VK delta G1/G2 are inconsistent")?;
    report["expected_sha256"] = json!(expected);
    report["observed_sha256"] = json!(hash);
    report["bytes"] = json!(before.bytes);
    report["same_descriptor_passes"] = json!(2);
    report["delta_g1_g2_consistent"] = json!(true);
    Ok((params, report))
}

struct PrivateDirectory { path: PathBuf, handle: File, filename: String }
impl PrivateDirectory {
    #[cfg(unix)]
    fn new(filename: &str) -> io::Result<Self> {
        require(!filename.is_empty() && !filename.contains('/'), "invalid private snapshot name")?;
        let parent = std::env::temp_dir().canonicalize()?;
        for _ in 0..16 {
            let mut random = [0u8; 16];
            OsRng.try_fill_bytes(&mut random).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let path = parent.join(format!("telos-validated-radix-{}", hex::encode(random)));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let handle = open_path(&path, true)?;
                    let m = handle.metadata()?;
                    require(m.mode() & 0o077 == 0 && m.uid() == unsafe { libc::geteuid() }, "private directory ownership/mode differs")?;
                    return Ok(Self { path, handle, filename: filename.to_owned() });
                },
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "could not create private snapshot directory"))
    }
    #[cfg(not(unix))]
    fn new(_: &str) -> io::Result<Self> { Err(invalid("private snapshots require Unix")) }
    fn file_path(&self) -> PathBuf { self.path.join(&self.filename) }
}
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = self.handle.set_permissions(fs::Permissions::from_mode(0o700));
        // No recursive removal, and no caller-selected arbitrary output tree.
        let _ = fs::remove_file(self.file_path());
        let _ = fs::remove_dir(&self.path);
    }
}

pub struct RadixSnapshot {
    directory: PrivateDirectory, file: File, file_identity: Identity,
    digest: String, pub validation: Value,
}
impl RadixSnapshot {
    pub fn directory(&self) -> io::Result<String> {
        self.directory.path.to_str().map(str::to_owned).ok_or_else(|| invalid("snapshot path is not UTF-8"))
    }
    pub fn recheck(&mut self) -> io::Result<()> {
        // The legacy library uses a pathname. Bind that pathname to our retained
        // descriptor as well as rehashing the SAME descriptor after verification.
        let mut named = open_path(&self.directory.file_path(), false)?;
        require(identity(&named.metadata()?) == self.file_identity, "private radix snapshot was replaced")?;
        hash_descriptor(&mut self.file, self.file_identity, &self.digest)?;
        hash_descriptor(&mut named, self.file_identity, &self.digest)?;
        Ok(())
    }
}

fn scan_radix(reader: &mut impl Read, layout: Layout) -> io::Result<Value> {
    let mut points = Points::default();
    points.g1(reader)?; points.g1(reader)?; points.g2(reader)?;
    // Matches phase2::MPCParameters::new at the pinned source revision exactly.
    for _ in 0..layout.domain { points.g1(reader)?; }
    for _ in 0..layout.domain { points.g2(reader)?; }
    for _ in 0..layout.domain { points.g1(reader)?; }
    for _ in 0..layout.domain { points.g1(reader)?; }
    for _ in 0..layout.domain - 1 { points.g1(reader)?; }
    let mut report = points.report();
    report["domain_size"] = json!(layout.domain);
    Ok(report)
}

pub fn snapshot_radix(path: &Path, expected: &str, layout: Layout) -> io::Result<RadixSnapshot> {
    require(valid_sha256(expected), "invalid expected radix SHA256")?;
    let mut source = open_path(path, false)?;
    let before = identity(&source.metadata()?);
    require(before.bytes == layout.radix_bytes() && before.bytes <= MAX_INPUT_BYTES,
        "radix length differs from exact compiled domain framing")?;
    let filename = format!("phase1radix2m{}", layout.domain.trailing_zeros());
    let directory = PrivateDirectory::new(&filename)?;
    #[cfg(unix)]
    let mut copy = OpenOptions::new().create_new(true).read(true).write(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(directory.file_path())?;
    #[cfg(not(unix))]
    let mut copy = return Err(invalid("private snapshots require Unix"));
    let mut reader = CheckedReader::new(&mut source, before.bytes, Some(&mut copy));
    let mut validation = scan_radix(&mut reader, layout)?;
    let digest = reader.finish(Some(expected))?;
    require(identity(&source.metadata()?) == before, "radix source changed during validation/copy")?;
    copy.sync_all()?;
    #[cfg(unix)]
    {
        copy.set_permissions(fs::Permissions::from_mode(0o400))?;
        directory.handle.set_permissions(fs::Permissions::from_mode(0o500))?;
    }
    let file_identity = identity(&copy.metadata()?);
    validation["expected_sha256"] = json!(expected);
    validation["observed_sha256"] = json!(digest);
    validation["bytes"] = json!(before.bytes);
    validation["private_snapshot"] = json!(true);
    validation["private_snapshot_trust"] = json!("trusted OS and executing UID; same-UID malicious code is outside this isolation boundary");
    let mut result = RadixSnapshot { directory, file: copy, file_identity, digest, validation };
    result.recheck()?;
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn layout() -> Layout { Layout::new(1, 1, 1, 2).unwrap() }
    fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
    fn fixture_file(bytes: &[u8]) -> PrivateDirectory {
        let dir = PrivateDirectory::new("input").unwrap();
        fs::write(dir.file_path(), bytes).unwrap();
        dir
    }
    #[test]
    fn receipt_reader_rejects_duplicate_keys_at_every_depth() {
        let valid = fixture_file(br#"{"schema":"stage","stage_validation":{"query_counts":{"a":1}}}"#);
        assert_eq!(read_small_json(&valid.file_path(), 1024).unwrap()["schema"], "stage");
        let duplicate_top = fixture_file(br#"{"schema":"approved","schema":"rejected"}"#);
        assert!(read_small_json(&duplicate_top.file_path(), 1024).unwrap_err()
            .to_string().contains("duplicate JSON key: schema"));
        let duplicate_nested = fixture_file(br#"{"stage_validation":{"query_counts":{"a":1,"a":2}}}"#);
        assert!(read_small_json(&duplicate_nested.file_path(), 1024).unwrap_err()
            .to_string().contains("duplicate JSON key: a"));
    }
    fn g1(out: &mut Vec<u8>) { out.extend_from_slice(G1Affine::one().into_uncompressed().as_ref()); }
    fn g2(out: &mut Vec<u8>) { out.extend_from_slice(G2Affine::one().into_uncompressed().as_ref()); }
    fn point(out: &mut Vec<u8>, fields: &mut Vec<(String, usize, usize)>, name: String, group: usize) {
        fields.push((name, out.len(), group));
        if group == 1 { g1(out); } else { g2(out); }
    }
    // Generator-only framing fixtures, NOT a valid setup or contribution. These
    // tests never call MPCParameters::new/contribute/verify or any proof API.
    fn transcript_fixture() -> (Vec<u8>, Vec<(String, usize, usize)>) {
        let mut bytes = Vec::new(); let mut fields = Vec::new();
        for (name, group) in [("alpha",1),("beta_g1",1),("beta_g2",2),("gamma",2),("delta_g1",1),("delta_g2",2)] {
            point(&mut bytes, &mut fields, name.to_owned(), group);
        }
        bytes.extend_from_slice(&1u32.to_be_bytes());
        point(&mut bytes, &mut fields, "ic".to_owned(), 1);
        for (name, group) in [("h",1),("l",1),("a",1),("b_g1",1),("b_g2",2)] {
            bytes.extend_from_slice(&1u32.to_be_bytes());
            point(&mut bytes, &mut fields, name.to_owned(), group);
        }
        bytes.extend_from_slice(&[0u8;64]);
        bytes.extend_from_slice(&2u32.to_be_bytes());
        for i in 0..2 {
            for (name, group) in [("delta_after",1),("s",1),("s_delta",1),("r_delta",2)] {
                point(&mut bytes, &mut fields, format!("record_{i}_{name}"), group);
            }
            bytes.extend_from_slice(&[i as u8;64]);
        }
        (bytes, fields)
    }
    fn radix_fixture() -> Vec<u8> {
        let mut bytes = Vec::new();
        g1(&mut bytes); g1(&mut bytes); g2(&mut bytes);
        for _ in 0..2 { g1(&mut bytes); }
        for _ in 0..2 { g2(&mut bytes); }
        for _ in 0..2 { g1(&mut bytes); }
        for _ in 0..2 { g1(&mut bytes); }
        g1(&mut bytes);
        bytes
    }

    #[test]
    fn canonical_generators_roundtrip_and_have_required_subgroup() {
        let mut points = Points::default(); let mut bytes = Vec::new();
        g1(&mut bytes); g2(&mut bytes);
        let mut reader = Cursor::new(bytes);
        assert_eq!(points.g1(&mut reader).unwrap(), G1Affine::one());
        assert_eq!(points.g2(&mut reader).unwrap(), G2Affine::one());
        assert_eq!((points.g1, points.g2), (1,1));
    }

    #[test]
    fn recovered_public_beta_is_rejected_by_strict_subgroup_gate() {
        // Unchanged public beta_g2 from the recovered Macanico tree archive,
        // offset128/length128. Provenance is beside the fixture. This invokes
        // only the NEW strict point loader, never a legacy verifier or proof API.
        let bytes = include_bytes!("fixtures/recovered_tree_beta_g2.bin");
        assert_eq!(digest(bytes), "7fb1641a2702aa4873167c7d08be72b76977956f0f61334bbb437a8ac328e5bb");
        let error = Points::default().g2(&mut Cursor::new(bytes)).unwrap_err();
        assert!(error.to_string().contains("NotInSubgroup"));
    }

    #[test]
    fn generator_framing_matches_pinned_library_reader_and_counts() {
        let (bytes, _) = transcript_fixture(); let dir = fixture_file(&bytes);
        let (params, report) = load_transcript(&dir.file_path(), &digest(&bytes), layout()).unwrap();
        assert_eq!(params.get_params().vk.beta_g2, G2Affine::one());
        assert_eq!(report["g1_points"], 14); assert_eq!(report["g2_points"], 6);
        assert_eq!(report["bytes"], bytes.len()); assert_eq!(report["same_descriptor_passes"], 2);
    }

    #[test]
    fn infinity_rejected_in_every_transcript_point_family() {
        let (bytes, fields) = transcript_fixture();
        for (name, offset, group) in fields {
            let mut changed = bytes.clone();
            let zero = if group == 1 { G1Affine::zero().into_uncompressed().as_ref().to_vec() }
                else { G2Affine::zero().into_uncompressed().as_ref().to_vec() };
            changed[offset..offset+zero.len()].copy_from_slice(&zero);
            let error = scan_transcript(&mut Cursor::new(changed), layout()).unwrap_err();
            assert!(error.to_string().contains("infinity"), "{}: {}", name, error);
        }
    }

    #[test]
    fn noncanonical_flags_and_short_points_rejected() {
        let mut bytes = G2Affine::one().into_uncompressed().as_ref().to_vec();
        bytes[0] |= 0x80;
        assert!(Points::default().g2(&mut Cursor::new(bytes)).is_err());
        assert!(Points::default().g1(&mut Cursor::new(vec![0;63])).is_err());
        assert!(Points::default().g2(&mut Cursor::new(vec![0;127])).is_err());
    }

    #[test]
    fn transcript_counts_truncation_and_trailing_data_rejected() {
        let (bytes, fields) = transcript_fixture();
        let mut offsets = vec![576];
        offsets.extend(fields.iter().filter(|(name,_,_)| ["h","l","a","b_g1","b_g2"].contains(&name.as_str())).map(|(_,offset,_)| offset-4));
        offsets.push(fields.iter().find(|(name,_,_)| name=="record_0_delta_after").unwrap().1-4);
        for offset in offsets {
            let mut changed = bytes.clone(); changed[offset..offset+4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(scan_transcript(&mut Cursor::new(changed), layout()).is_err());
        }
        let mut changed = bytes.clone(); changed.pop();
        assert!(scan_transcript(&mut Cursor::new(changed), layout()).is_err());
        let mut changed = bytes; changed.push(0);
        let dir = fixture_file(&changed);
        assert!(load_transcript(&dir.file_path(), &digest(&changed), layout()).is_err());
    }

    #[test]
    fn incorrect_transcript_digest_and_dimensions_rejected() {
        let (bytes, _) = transcript_fixture(); let dir = fixture_file(&bytes);
        assert!(load_transcript(&dir.file_path(), &"00".repeat(32), layout()).is_err());
        assert!(Layout::new(1,1,usize::MAX,2).is_err());
        assert!(Layout::new(1,1,1,MAX_CONTRIBUTIONS+1).is_err());
        assert!(Layout::new(1,1,MAX_DOMAIN as usize,2).is_err());
        assert!(Layout::new(65,1,1,2).is_err());
    }

    #[test]
    fn bounded_contribution_anchors_accept_distinct_and_reject_bad_lists() {
        let good = vec!["ab".repeat(64), "cd".repeat(64)];
        let bytes = serde_json::to_vec(&good).unwrap(); let dir = fixture_file(&bytes);
        let (parsed, hash) = read_anchors(&dir.file_path()).unwrap();
        assert_eq!(parsed, good); assert_eq!(hash, digest(&bytes));
        for bad in [vec!["ab".repeat(64)], vec!["ab".repeat(64),"ab".repeat(64)], vec!["AB".repeat(64),"cd".repeat(64)]] {
            fs::write(dir.file_path(), serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(read_anchors(&dir.file_path()).is_err());
        }
        let file = OpenOptions::new().write(true).open(dir.file_path()).unwrap();
        file.set_len(MAX_ANCHOR_BYTES+1).unwrap();
        assert!(read_anchors(&dir.file_path()).is_err());
    }

    #[test]
    fn symlinks_in_leaf_or_parent_and_parent_components_rejected() {
        let dir = fixture_file(b"ordinary input");
        let links = PrivateDirectory::new("input").unwrap();
        std::os::unix::fs::symlink(dir.file_path(), links.file_path()).unwrap();
        assert!(open_path(&links.file_path(), false).is_err());
        fs::remove_file(links.file_path()).unwrap();
        std::os::unix::fs::symlink(&dir.path, links.file_path()).unwrap();
        assert!(open_path(&links.file_path().join("input"), false).is_err());
        assert!(open_path(&dir.path.join("../input"), false).is_err());
    }

    #[test]
    fn same_descriptor_mutation_is_detected() {
        let dir = fixture_file(b"first contents");
        let mut file = open_path(&dir.file_path(), false).unwrap(); let original = identity(&file.metadata().unwrap());
        fs::write(dir.file_path(), b"changed contents").unwrap();
        assert!(hash_descriptor(&mut file, original, &digest(b"first contents")).is_err());
    }

    #[test]
    fn radix_snapshot_validates_every_point_and_isolated_copy() {
        let bytes = radix_fixture(); assert_eq!(bytes.len() as u64, layout().radix_bytes());
        let dir = fixture_file(&bytes);
        let mut snapshot = snapshot_radix(&dir.file_path(), &digest(&bytes), layout()).unwrap();
        assert_eq!(snapshot.validation["g1_points"], 9); assert_eq!(snapshot.validation["g2_points"], 3);
        assert_eq!(snapshot.file.metadata().unwrap().mode() & 0o777, 0o400);
        assert_eq!(snapshot.directory.handle.metadata().unwrap().mode() & 0o077, 0);
        fs::write(dir.file_path(), b"source changed after validated copy").unwrap();
        snapshot.recheck().unwrap();
        let private_path = snapshot.directory.path.clone();
        drop(snapshot); assert!(!private_path.exists());
    }

    #[test]
    fn radix_size_digest_infinity_and_snapshot_mutation_rejected() {
        let bytes = radix_fixture(); let dir = fixture_file(&bytes);
        assert!(snapshot_radix(&dir.file_path(), &"00".repeat(32), layout()).is_err());
        for offset in [128, 384, 512] { // Header and both coefficient G2 entries.
            let mut changed = bytes.clone();
            changed[offset..offset+128].copy_from_slice(G2Affine::zero().into_uncompressed().as_ref());
            fs::write(dir.file_path(), &changed).unwrap();
            assert!(snapshot_radix(&dir.file_path(), &digest(&changed), layout()).is_err());
        }
        let mut changed = bytes.clone(); changed.push(0);
        fs::write(dir.file_path(), &changed).unwrap();
        assert!(snapshot_radix(&dir.file_path(), &digest(&changed), layout()).is_err());
        fs::write(dir.file_path(), &bytes).unwrap();
        let mut snapshot = snapshot_radix(&dir.file_path(), &digest(&bytes), layout()).unwrap();
        snapshot.file.set_len(bytes.len() as u64-1).unwrap();
        assert!(snapshot.recheck().is_err());
    }
}
