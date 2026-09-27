#!/usr/bin/env python3
"""Seal unsafe Stage 0 WASM builds, optionally with Chromium key-parse evidence."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Optional

spec = importlib.util.spec_from_file_location("verify_source", Path(__file__).with_name("verify_source.py"))
assert spec is not None and spec.loader is not None
verify_source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_source)
CRATE = verify_source.CRATE
ROOT = verify_source.ROOT
check_source = verify_source.check_source
sha256 = verify_source.sha256


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def event_pull_request_head() -> Optional[str]:
    """Record and check the PR head independently of GitHub's merge ref."""
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    if event_name is None:
        return None
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise SystemExit("HOLD: GitHub event payload is missing")
    event = json.loads(Path(event_path).read_text())
    checkout_head = command("git", "rev-parse", "HEAD")
    if event_name == "pull_request":
        pr_head = event["pull_request"]["head"]["sha"]
        if checkout_head != pr_head:
            raise SystemExit("HOLD: checkout is not the pull-request head")
        return pr_head
    if event_name == "workflow_dispatch" and checkout_head != os.environ.get("GITHUB_SHA"):
        raise SystemExit("HOLD: checkout is not the dispatched commit")
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("wasm_bindgen_bin", type=Path)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    out = args.evidence_dir.resolve()
    bindgen = args.wasm_bindgen_bin.resolve()
    pin = check_source()
    pr_head = event_pull_request_head()
    files = {
        "pkg/stage0.js": out / "pkg/stage0.js",
        "pkg/stage0_bg.wasm": out / "pkg/stage0_bg.wasm",
    }
    if not args.build_only:
        files["browser-result.json"] = out / "browser-result.json"
    for label, path in files.items():
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"HOLD: missing or empty generated artifact: {label}")
    if files["pkg/stage0_bg.wasm"].open("rb").read(8) != b"\x00asm\x01\x00\x00\x00":
        raise SystemExit("HOLD: generated WASM header invalid")
    if not args.build_only:
        browser = json.loads(files["browser-result.json"].read_text())
        required_true = (
            "exact_key_sha256_checked_in_browser",
            "exact_key_parsed_in_browser",
            "empty_key_rejected_in_browser",
            "changed_byte_rejected_in_browser",
            "unsupported_kind_rejected_in_browser",
        )
        if browser.get("schema") != "telos-pr7-unsafe-stage0-browser-key-test-v1":
            raise SystemExit("HOLD: browser fixture schema mismatch")
        if browser.get("browser_proof_tested") is not False:
            raise SystemExit("HOLD: browser proof status is not explicitly untested")
        if browser.get("status") != "UNSAFE_STAGE0_NO_GO" or any(
            browser.get(field) is not True for field in required_true
        ):
            raise SystemExit("HOLD: browser fixture controls incomplete")
        if browser.get("source_tree_matched_in_browser") is not True:
            raise SystemExit("HOLD: browser source-tree check incomplete")
        if browser.get("source_tree") != pin["vendored_pr7_git_tree"]:
            raise SystemExit("HOLD: browser source-tree mismatch")
        if browser.get("parameter_sha256") != pin["converted_stage0_browser_key_sha256"]:
            raise SystemExit("HOLD: browser parameter-hash mismatch")
    bindgen_version = command(str(bindgen), "--version")
    if bindgen_version != "wasm-bindgen 0.2.118":
        raise SystemExit(f"HOLD: wasm-bindgen CLI drift: {bindgen_version}")
    rust_version = command("rustc", "+1.94.0", "--version")
    if not rust_version.startswith("rustc 1.94.0 "):
        raise SystemExit(f"HOLD: rust toolchain drift: {rust_version}")
    manifest = {
        "schema": "telos-pr7-unsafe-stage0-browser-evidence-v1",
        "status": "UNSAFE_STAGE0_NO_GO",
        "qualification": {
            "browser_wasm_built": True,
            "browser_stage0_key_parse_tested": not args.build_only,
            "browser_proof_tested": False,
            "qualified_ceremony": False,
            "wallet_worker_wired": False,
            "production_release_approved": False,
        },
        "source": {
            "head": command("git", "rev-parse", "HEAD"),
            "event_pull_request_head": pr_head,
            "git_tree": command("git", "rev-parse", "HEAD^{tree}"),
            "proof_git_tree": command("git", "rev-parse", "HEAD:packages/wtlos-pr7-proof"),
            "stage0_wasm_git_tree": command("git", "rev-parse", "HEAD:packages/wtlos-pr7-stage0-wasm"),
            "workflow_git_blob": command(
                "git", "rev-parse", "HEAD:.github/workflows/unsafe-pr7-stage0-browser.yml"
            ),
            "vendored_pr7_git_tree": pin["vendored_pr7_git_tree"],
            "phase2_upstream_git_commit": pin["phase2_upstream_git_commit"],
            "phase2_upstream_package_tree": pin["phase2_upstream_package_tree"],
            "phase2_vendored_package_tree": pin["phase2_vendored_package_tree"],
            "phase2_origin_certificate_sha256": pin["phase2_origin_certificate_sha256"],
            "phase2_vendored_manifest_sha256": pin["phase2_vendored_manifest_sha256"],
            "cargo_lock_sha256": sha256(CRATE / "Cargo.lock"),
            "proof_cargo_lock_sha256": sha256(CRATE.parent / "wtlos-pr7-proof/Cargo.lock"),
            "adapter_sha256": sha256(CRATE / "src/lib.rs"),
            "source_pin_sha256": sha256(CRATE / "SOURCE-PIN.json"),
            "proof_domain_codec_sha256": pin["proof_domain_codec_sha256"],
            "proof_source_pin_sha256": sha256(CRATE.parent / "wtlos-pr7-proof/SOURCE-PIN.json"),
            "transfer_stage0_mpc_sha256": pin["transfer_stage0_mpc_sha256"],
            "converted_stage0_browser_key_sha256": pin["converted_stage0_browser_key_sha256"],
        },
        "toolchain": {
            "rustc": rust_version,
            "wasm_bindgen_cli": bindgen_version,
            "node": command("node", "--version"),
        },
        "files_sha256": {label: sha256(path) for label, path in files.items()},
    }
    manifest_path = out / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    files["MANIFEST.json"] = manifest_path
    (out / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {label}\n" for label, path in sorted(files.items()))
    )
    print("PASS: generated JS/WASM sealed as UNSAFE_STAGE0_NO_GO; browser key parse tested:", not args.build_only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
