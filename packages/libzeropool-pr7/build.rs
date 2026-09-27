use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, fs, path::{Path, PathBuf}};

fn collect(root: &Path, at: &Path, found: &mut BTreeMap<String, String>) -> Result<(), String> {
    for entry in fs::read_dir(at).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || name == "target" || name == ".DS_Store" || name.starts_with("._") {
            continue;
        }
        let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
        if relative == Path::new("formal/ceremony-source-lock.json") { continue; }
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() { return Err(format!("symlink in source: {}", relative.display())); }
        if metadata.is_dir() { collect(root, &path, found)?; }
        else if metadata.is_file() {
            let bytes = fs::read(&path).map_err(|e| e.to_string())?;
            let key = relative.to_str().ok_or("non-UTF8 source path")?.replace('\\', "/");
            found.insert(key, format!("{:x}", Sha256::digest(bytes)));
            println!("cargo:rerun-if-changed={}", relative.display());
        } else { return Err(format!("unsupported source type: {}", relative.display())); }
    }
    Ok(())
}

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let lock = root.join("formal/ceremony-source-lock.json");
    println!("cargo:rerun-if-changed={}", lock.display());
    let approved: serde_json::Value = serde_json::from_slice(&fs::read(&lock).expect("source lock exists"))
        .expect("source lock parses");
    assert_eq!(approved["schema"], "telos-privacy-pr3-contributor-source-lock-v1");
    let expected: BTreeMap<String, String> = serde_json::from_value(approved["files"].clone())
        .expect("source lock files object");
    assert!(!expected.is_empty(), "empty source lock");
    let mut observed = BTreeMap::new();
    collect(&root, &root, &mut observed).expect("source scan");
    assert_eq!(observed, expected, "source differs from approved ceremony source lock");
}
