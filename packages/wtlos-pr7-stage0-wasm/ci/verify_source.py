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
EXPECTED_PROOF_DOMAIN_SHA256 = "b4a9cfc6c3c46231231d76028bdcfb290504d09f83617a3acfbf2d2df31e1918"
EXPECTED_MPC_SHA256 = "d00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30"
EXPECTED_KEY_SHA256 = "44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1"
EXPECTED_KEY_BYTES = 72_498_469
EXPECTED_BINDGEN_VERSION = "0.2.118"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_build_inputs() -> None:
    """Bind the bytes being built to the recorded Git source identity."""
    guarded_paths = (
        ".github/workflows/unsafe-pr7-stage0-browser.yml",
        "packages/libzeropool-pr7",
        "packages/wtlos-pr7-proof",
        "packages/wtlos-pr7-stage0-wasm",
    )
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", *guarded_paths],
        cwd=ROOT,
        text=True,
    ).strip()
    assert not status, f"guarded build inputs are dirty or untracked:\n{status}"

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


def check_source() -> dict:
    check_build_inputs()
    pin = json.loads((CRATE / "SOURCE-PIN.json").read_text())
    assert pin["schema"] == "telos-pr7-browser-stage0-adapter-v1"
    assert pin["wallet_main_base_commit"] == EXPECTED_WALLET_MAIN_BASE
    assert pin["vendored_pr7_git_tree"] == EXPECTED_SOURCE_TREE
    assert pin["proof_domain_codec_sha256"] == EXPECTED_PROOF_DOMAIN_SHA256
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
    lock = (CRATE / "Cargo.lock").read_text()
    versions = []
    for block in lock.split("[[package]]"):
        if re.search(r'^name = "wasm-bindgen"$', block, re.MULTILINE):
            match = re.search(r'^version = "([^"]+)"$', block, re.MULTILINE)
            assert match is not None, "wasm-bindgen lock version missing"
            versions.append(match.group(1))
    assert versions == [EXPECTED_BINDGEN_VERSION], f"wasm-bindgen lock drift: {versions}"
    crate_manifest = (CRATE / "Cargo.toml").read_text()
    assert 'features = ["serde_support", "wasm"]' in crate_manifest, "WASM entropy feature missing"
    lib = (CRATE / "src/lib.rs").read_text()
    assert EXPECTED_MPC_SHA256 in lib and EXPECTED_KEY_SHA256 in lib
    assert "pub struct UnsafeStage0Params" in lib and "unsafeStage0Tx" in lib
    return pin


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=Path, help="exact unqualified converted Stage 0 test key")
    args = parser.parse_args()
    check_source()
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
