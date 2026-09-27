#!/usr/bin/env python3
"""Fail-closed source and optional test-key checks for unsafe Stage 0 WASM."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

CRATE = Path(__file__).resolve().parents[1]
ROOT = CRATE.parents[1]
PROOF_CRATE = ROOT / "packages/wtlos-pr7-proof"
EXPECTED_SOURCE_TREE = "7a22196e1d4a791b452a6140bdfa915298f3f1da"
EXPECTED_WALLET_MAIN_BASE = "4354c9c279eb40c3a4164d97695985124285d9ce"
EXPECTED_PR76_BROWSER_COMMIT = "ef96fba05c5d4e5ba2b656b319f5b2969df7714a"
EXPECTED_WALLET_PROFILE_COMMIT = "c110f6eeb845081564040685dd07c8c1fe614cb3"
EXPECTED_PROOF_DOMAIN_SHA256 = "b4a9cfc6c3c46231231d76028bdcfb290504d09f83617a3acfbf2d2df31e1918"
EXPECTED_MPC_SHA256 = "d00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30"
EXPECTED_KEY_SHA256 = "44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1"
EXPECTED_KEY_BYTES = 72_498_469
EXPECTED_BINDGEN_VERSION = "0.2.118"
EXPECTED_CARGO_LOCK_SHA256 = "f63833eaf5cc76827bf468537ad97e963ad6d1e5db30d78ffbef4b91a26581fa"
EXPECTED_PROOF_CARGO_LOCK_SHA256 = "d6df95a9c67b700271c755b6d12baacb8ade1f5af8a045c1859f33365d80180e"
PHASE2_VENDOR = CRATE / "vendor/fawkes-crypto-phase2-0.2.3"
PHASE2_ORIGIN = CRATE / "ci/phase2-origin.json"
EXPECTED_PHASE2_COMMIT = "0d286cc94af78e96d3d1184b0e38246714afa838"
EXPECTED_PHASE2_ORIGIN_TREE = "7f15bbc81038e51c6828920a9424ef16cb0dbddb"
EXPECTED_PHASE2_VENDOR_TREE = "d7630c115be08f1aad06f66b07b23d243e81bffd"
EXPECTED_PHASE2_CERT_SHA256 = "1ba55687c39e283d0b796a4e1a21a228d586612a411186b67e4a2502395c4612"
EXPECTED_PHASE2_MANIFEST_SHA256 = "f345a6eed23f2085452266ec26b0b2e6ec945031fd3230823f4f64162bf8d4b4"
DISPATCH_GUARD_SHA256 = {
    "packages/zkbob-client-js/src/client.ts":
        "0c85c24a5e83c72387df104b80172364c2e593184edb09e041cf29644e144cb6",
    "packages/zkbob-client-js/src/worker.ts":
        "67fd9a4644a995bc858dca664c203aa3e538b51e9ef682163336ac395b2be7c8",
    "packages/zkbob-client-js/src/config.ts":
        "5c9707f116e8aa748d6fbfc42e818858cc6aa31b7c7d6aaa4535b3d5daca1586",
    "packages/zkbob-client-js/test/wtlos-pr7-prover-dispatch.test.cjs":
        "3f9b1eb2ae7e490b8b6563fdfc02dab53d4f80b2f53e03c8ff1fc4d926a5b3c0",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_build_inputs() -> None:
    """Bind the composed browser and wallet bytes to their reviewed parents."""
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
    ).strip()
    assert not status, f"repository is dirty or has untracked files:\n{status}"
    for parent in (EXPECTED_WALLET_MAIN_BASE, EXPECTED_PR76_BROWSER_COMMIT,
                   EXPECTED_WALLET_PROFILE_COMMIT):
        subprocess.check_call(["git", "merge-base", "--is-ancestor", parent, "HEAD"], cwd=ROOT)

    def changes(revision: str) -> set[str]:
        output = subprocess.check_output(
            ["git", "diff", "--name-only", "-z", EXPECTED_WALLET_MAIN_BASE, revision, "--"],
            cwd=ROOT,
        )
        return {raw.decode() for raw in output.split(b"\0") if raw}

    def blob(revision: str, path: str) -> str:
        return subprocess.check_output(
            ["git", "rev-parse", f"{revision}:{path}"], cwd=ROOT, text=True
        ).strip()

    browser_changes = changes(EXPECTED_PR76_BROWSER_COMMIT)
    wallet_changes = changes(EXPECTED_WALLET_PROFILE_COMMIT) - browser_changes
    build_evidence_paths = {
        ".github/workflows/unsafe-pr7-composed-wallet-build.yml",
        ".github/scripts/unsafe-pr7-composed-wallet-build.sh",
    }
    changed = changes("HEAD")
    expected = browser_changes | wallet_changes | build_evidence_paths | set(DISPATCH_GUARD_SHA256)
    assert changed == expected, (
        f"composed source path set drift: extra={sorted(changed - expected)}, "
        f"missing={sorted(expected - changed)}"
    )
    this_verifier = Path(__file__).relative_to(ROOT).as_posix()
    for path in browser_changes:
        # This verifier is deliberately extended for the composed source tree;
        # the release receipt pins the resulting commit and full tree.
        if path != this_verifier:
            assert blob("HEAD", path) == blob(EXPECTED_PR76_BROWSER_COMMIT, path), (
                f"PR76 browser source drift: {path}"
            )
    for path in wallet_changes:
        if path not in DISPATCH_GUARD_SHA256:
            assert blob("HEAD", path) == blob(EXPECTED_WALLET_PROFILE_COMMIT, path), (
                f"WTLOS wallet profile source drift: {path}"
            )
    for path, digest in DISPATCH_GUARD_SHA256.items():
        assert sha256(ROOT / path) == digest, f"WTLOS dispatch guard drift: {path}"

    path_attribute = re.compile(r'^\s*#\[path\s*=\s*"([^"]+)"\]\s*$', re.MULTILINE)
    for crate in (PROOF_CRATE, CRATE):
        for source in sorted((crate / "src").rglob("*.rs")):
            for relative in path_attribute.findall(source.read_text()):
                target = (source.parent / relative).resolve()
                assert target.is_relative_to(ROOT), (
                    f"Rust #[path] input escapes repository: {source.relative_to(ROOT)} -> {target}"
                )
                assert target.is_file(), (
                    f"missing Rust #[path] input: {source.relative_to(ROOT)} -> "
                    f"{target.relative_to(ROOT)}"
                )
                subprocess.check_call(
                    ["git", "ls-files", "--error-unmatch", str(target.relative_to(ROOT))],
                    cwd=ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )


def check_phase2_patch(pin: dict) -> None:
    """Keep the original PR7 tree intact and bind the distinct Phase 2 manifest."""
    assert pin["phase2_upstream_git_commit"] == EXPECTED_PHASE2_COMMIT
    assert pin["phase2_upstream_package_tree"] == EXPECTED_PHASE2_ORIGIN_TREE
    assert pin["phase2_vendored_package_tree"] == EXPECTED_PHASE2_VENDOR_TREE
    assert pin["phase2_origin_certificate_sha256"] == EXPECTED_PHASE2_CERT_SHA256
    assert pin["phase2_vendored_manifest_sha256"] == EXPECTED_PHASE2_MANIFEST_SHA256
    assert sha256(PHASE2_ORIGIN) == EXPECTED_PHASE2_CERT_SHA256
    origin = json.loads(PHASE2_ORIGIN.read_text())
    assert origin["schema"] == "telos-stage0-phase2-upstream-files-v1"
    assert origin["upstream_url"] == "https://github.com/zkBob/phase2-bn254"
    assert origin["upstream_commit"] == EXPECTED_PHASE2_COMMIT
    assert origin["upstream_package_path"] == "phase2"
    assert origin["upstream_package_tree"] == EXPECTED_PHASE2_ORIGIN_TREE
    files = {}
    for path in PHASE2_VENDOR.rglob("*"):
        assert not path.is_symlink(), f"Phase 2 vendor symlink: {path}"
        if path.is_file():
            files[path.relative_to(PHASE2_VENDOR).as_posix()] = sha256(path)
    assert files.keys() == origin["files_sha256"].keys(), "Phase 2 vendor file set differs from upstream"
    assert files["Cargo.toml"] == EXPECTED_PHASE2_MANIFEST_SHA256
    for path, expected in origin["files_sha256"].items():
        if path != "Cargo.toml":
            assert files[path] == expected, f"Phase 2 upstream file changed: {path}"

    vendor_tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD:packages/wtlos-pr7-stage0-wasm/vendor/fawkes-crypto-phase2-0.2.3"],
        cwd=ROOT, text=True,
    ).strip()
    assert vendor_tree == EXPECTED_PHASE2_VENDOR_TREE, "Phase 2 vendor Git tree drift"
    crate_manifest = (CRATE / "Cargo.toml").read_text()
    assert (
        '[patch."https://github.com/zkBob/phase2-bn254"]\n'
        'fawkes-crypto-phase2 = { path = "vendor/fawkes-crypto-phase2-0.2.3" }'
    ) in crate_manifest
    phase2_manifest = (PHASE2_VENDOR / "Cargo.toml").read_text()
    assert phase2_manifest.count('rust-crypto = { version = "0.2", optional = true }') == 1
    assert 'default = ["rust-crypto"]' in phase2_manifest
    assert 'default = ["bellman_ce/multicore", "rust-crypto"]' not in phase2_manifest
    assert (
        '[target.\'cfg(not(target_arch = "wasm32"))\'.dependencies]\n'
        'bellman_ce = { package = "fawkes-crypto-zkbob-bellman_ce", version="0.4.0", '
        'git = "https://github.com/zkBob/phase2-bn254", branch = "master", '
        'default-features = false, features = ["multicore"] }'
    ) in phase2_manifest
    assert (
        '[target.\'cfg(target_arch = "wasm32")\'.dependencies]\n'
        'bellman_ce = { package = "fawkes-crypto-zkbob-bellman_ce", version="0.4.0", '
        'git = "https://github.com/zkBob/phase2-bn254", branch = "master", '
        'default-features = false, features = ["wasm"] }'
    ) in phase2_manifest
    assert 'git = "https://github.com/zkBob/phase2-bn254", branch = "master"' in phase2_manifest
    phase2_packages = [
        block for block in (CRATE / "Cargo.lock").read_text().split("[[package]]")
        if re.search(r'^name = "fawkes-crypto-phase2"$', block, re.MULTILINE)
    ]
    assert len(phase2_packages) == 1 and not re.search(r'^source = ', phase2_packages[0], re.MULTILINE), (
        "Cargo.lock must resolve Phase 2 to the pinned local variant"
    )


def check_upstream_phase2_repo(repo: Path) -> None:
    """Optional independent replay against the pinned upstream Git object."""
    origin = json.loads(PHASE2_ORIGIN.read_text())
    tree = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{EXPECTED_PHASE2_COMMIT}:phase2"], text=True
    ).strip()
    assert tree == EXPECTED_PHASE2_ORIGIN_TREE, "upstream Phase 2 tree mismatch"
    paths = subprocess.check_output(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "-z", EXPECTED_PHASE2_COMMIT, "phase2"]
    ).split(b"\0")
    actual = {}
    for raw in paths:
        if raw:
            full = raw.decode()
            data = subprocess.check_output(
                ["git", "-C", str(repo), "show", f"{EXPECTED_PHASE2_COMMIT}:{full}"]
            )
            actual[full.removeprefix("phase2/")] = hashlib.sha256(data).hexdigest()
    assert actual == origin["files_sha256"], "upstream Phase 2 certificate mismatch"


def check_source() -> dict:
    check_build_inputs()
    pin = json.loads((CRATE / "SOURCE-PIN.json").read_text())
    assert pin["schema"] == "telos-pr7-browser-stage0-adapter-v1"
    assert pin["wallet_main_base_commit"] == EXPECTED_WALLET_MAIN_BASE
    assert pin["vendored_pr7_git_tree"] == EXPECTED_SOURCE_TREE
    assert pin["proof_domain_codec_sha256"] == EXPECTED_PROOF_DOMAIN_SHA256
    assert pin["cargo_lock_sha256"] == EXPECTED_CARGO_LOCK_SHA256
    assert pin["proof_cargo_lock_sha256"] == EXPECTED_PROOF_CARGO_LOCK_SHA256
    assert sha256(CRATE / "Cargo.lock") == EXPECTED_CARGO_LOCK_SHA256
    assert sha256(PROOF_CRATE / "Cargo.lock") == EXPECTED_PROOF_CARGO_LOCK_SHA256
    proof = CRATE.parent / "wtlos-pr7-proof"
    assert sha256(proof / "src/domain.rs") == EXPECTED_PROOF_DOMAIN_SHA256
    proof_pin = json.loads((proof / "SOURCE-PIN.json").read_text())
    assert proof_pin["domain_codec_origin_commit"] == "e6aa95a69e6246028f084c46f5258798bf7533ec"
    assert proof_pin["domain_codec_origin_path"] == "packages/libzkbob-rs/src/wtlos_v1_domain.rs"
    assert proof_pin["domain_codec_sha256"] == EXPECTED_PROOF_DOMAIN_SHA256
    assert pin["transfer_stage0_mpc_sha256"] == EXPECTED_MPC_SHA256
    assert pin["converted_stage0_browser_key_sha256"] == EXPECTED_KEY_SHA256
    for gate in (
        "qualified_ceremony",
        "browser_wasm_built",
        "wallet_worker_wired",
        "production_release_approved",
    ):
        assert pin[gate] is False, f"unsafe Stage 0 gate unexpectedly enabled: {gate}"
    actual_tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD:packages/libzeropool-pr7"], cwd=ROOT, text=True
    ).strip()
    assert actual_tree == EXPECTED_SOURCE_TREE, "vendored circuit tree drift"
    check_phase2_patch(pin)
    lock = (CRATE / "Cargo.lock").read_text()
    versions = []
    for block in lock.split("[[package]]"):
        if re.search(r'^name = "wasm-bindgen"$', block, re.MULTILINE):
            match = re.search(r'^version = "([^"]+)"$', block, re.MULTILINE)
            assert match is not None, "wasm-bindgen lock version missing"
            versions.append(match.group(1))
    assert versions == [EXPECTED_BINDGEN_VERSION], f"wasm-bindgen lock drift: {versions}"
    crate_manifest = (CRATE / "Cargo.toml").read_text()
    proof_manifest = (PROOF_CRATE / "Cargo.toml").read_text()
    assert 'features = ["in3out127"]' in crate_manifest and 'features = ["in3out127"]' in proof_manifest
    assert "cli_libzeropool_setup" not in crate_manifest and "cli_libzeropool_setup" not in proof_manifest
    assert 'features = ["serde_support", "wasm", "backend_bellman_groth16"]' in crate_manifest, (
        "WASM entropy or Groth16 backend feature missing"
    )
    lib = (CRATE / "src/lib.rs").read_text()
    assert EXPECTED_MPC_SHA256 in lib and EXPECTED_KEY_SHA256 in lib
    assert "pub struct UnsafeStage0Params" in lib and "unsafeStage0Tx" in lib
    return pin


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=Path, help="exact unqualified converted Stage 0 test key")
    parser.add_argument("--upstream-phase2-repo", type=Path, help="replay the Phase 2 origin certificate against a local Git checkout")
    args = parser.parse_args()
    check_source()
    if args.upstream_phase2_repo is not None:
        check_upstream_phase2_repo(args.upstream_phase2_repo)
    if args.key is not None:
        if not args.key.is_file():
            raise SystemExit("HOLD: exact converted Stage 0 key is missing")
        if args.key.stat().st_size != EXPECTED_KEY_BYTES:
            raise SystemExit("HOLD: converted Stage 0 key byte length mismatch")
        if sha256(args.key) != EXPECTED_KEY_SHA256:
            raise SystemExit("HOLD: converted Stage 0 key SHA-256 mismatch")
        print("PASS: exact unqualified Stage 0 test key bytes (still NO-GO)")
    else:
        print("PASS: source and lock pins (key/browser evidence absent; NO-GO)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
