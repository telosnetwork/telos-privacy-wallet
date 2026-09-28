#!/usr/bin/env bash
# Build-only qualification for the composed PR76 + release-v2 wallet source.
# The generated legacy WASM does not provide the PR7 proving capability.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
EVIDENCE_DIR="${WALLET_BUILD_EVIDENCE_DIR:?set WALLET_BUILD_EVIDENCE_DIR}"
WASM_BINDGEN_BIN="${WASM_BINDGEN_BIN:?set WASM_BINDGEN_BIN}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}"
export CARGO_TARGET_DIR
mkdir -p "$EVIDENCE_DIR"

if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo 'HOLD: source checkout is dirty before build' >&2
  exit 1
fi
python3 -I -B packages/wtlos-pr7-stage0-wasm/ci/verify_source.py

set -x
test "$(rustc +1.94.0 --version)" = 'rustc 1.94.0 (4a4ef493e 2026-03-02)'
test "$(rustc +nightly-2026-05-17 --version)" = 'rustc 1.97.0-nightly (d3cd04068 2026-05-16)'
test "$("$WASM_BINDGEN_BIN" --version)" = 'wasm-bindgen 0.2.106'
test "$(node --version)" = 'v22.22.0'
test "$(yarn --version)" = '1.22.22'
rustup target list --installed --toolchain 1.94.0 | grep -qx wasm32-unknown-unknown
rustup target list --installed --toolchain nightly-2026-05-17 | grep -qx wasm32-unknown-unknown
rustup component list --installed --toolchain nightly-2026-05-17 | grep -Eq '^rust-src($|[-[:space:]])'
set +x

WASM_CRATE="$ROOT/packages/libzkbob-rs-wasm"
WASM_IMAGE="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/libzkbob_rs_wasm_web.wasm"

cargo +1.94.0 build --locked --release --target wasm32-unknown-unknown \
  --manifest-path "$WASM_CRATE/Cargo.toml" --features web
"$WASM_BINDGEN_BIN" "$WASM_IMAGE" --target web \
  --out-name libzkbob_rs_wasm_web --out-dir "$WASM_CRATE/web"

RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
  cargo +nightly-2026-05-17 build --locked --release \
  --target wasm32-unknown-unknown --manifest-path "$WASM_CRATE/Cargo.toml" \
  --features web,multicore -Z build-std=panic_abort,std
"$WASM_BINDGEN_BIN" "$WASM_IMAGE" --target web \
  --out-name libzkbob_rs_wasm_web --out-dir "$WASM_CRATE/web-mt"

python3 - "$WASM_CRATE" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
for variant, package_name in (
    ("web", "libzkbob-rs-wasm-web"),
    ("web-mt", "libzkbob-rs-wasm-web-mt"),
):
    output = root / variant
    expected = (
        output / "libzkbob_rs_wasm_web.js",
        output / "libzkbob_rs_wasm_web_bg.wasm",
        output / "libzkbob_rs_wasm_web.d.ts",
    )
    for path in expected:
        if not path.is_file():
            raise SystemExit(f"HOLD: missing generated {path}")
    for dts in output.glob("*.d.ts"):
        if dts.name.endswith("_bg.wasm.d.ts"):
            dts.unlink()
        else:
            dts.write_text("\n".join(
                line for line in dts.read_text().splitlines()
                if "BroccoliDestroyInstance" not in line
            ) + "\n")
    if variant == "web-mt":
        for helper in (output / "snippets").rglob("workerHelpers.js"):
            helper.write_text(helper.read_text().replace(
                "'../../..'", "'../../../libzkbob_rs_wasm_web.js'"
            ))
    package = {
        "name": package_name,
        "version": "1.7.0",
        "module": "libzkbob_rs_wasm_web.js",
        "main": "libzkbob_rs_wasm_web.js",
        "types": "libzkbob_rs_wasm_web.d.ts",
        "sideEffects": False,
        "files": ["*.js", "*.wasm", "*.d.ts", "snippets"],
    }
    (output / "package.json").write_text(json.dumps(package, indent=2) + "\n")
PY

# The repository's preinstall runs a floating-toolchain WASM generator. These
# source-bound packages already exist, so suppress lifecycle scripts here.
yarn install --frozen-lockfile --ignore-scripts --non-interactive --network-concurrency 1
node --test packages/zkbob-client-js/test/wtlos-pr7-prover-dispatch.test.cjs
node --test packages/zkbob-client-js/test/wtlos-browser-artifact-inspection.test.cjs
yarn workspace zkbob-client-js run check
yarn workspace zkbob-client-js run build
CI=false GENERATE_SOURCEMAP=false REACT_APP_CONFIG=dev \
  NODE_OPTIONS=--max-old-space-size=6144 \
  REACT_APP_WALLETCONNECT_PROJECT_ID=ci-placeholder \
  yarn workspace zktelos-wallet run build

python3 - "$ROOT" "$EVIDENCE_DIR" "$WASM_BINDGEN_BIN" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root, evidence, bindgen = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
def run(*args):
    return subprocess.check_output(args, cwd=root, text=True).strip()
def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()
outputs = {}
for subdir in (
    "packages/libzkbob-rs-wasm/web",
    "packages/libzkbob-rs-wasm/web-mt",
    "packages/zkbob-client-js/lib",
    "apps/zktelos-wallet/build",
):
    folder = root / subdir
    if not folder.is_dir():
        raise SystemExit(f"HOLD: missing build output {subdir}")
    files = {p.relative_to(root).as_posix(): digest(p)
             for p in sorted(folder.rglob("*")) if p.is_file()}
    if not files:
        raise SystemExit(f"HOLD: empty build output {subdir}")
    outputs.update(files)
manifest = {
    "schema": "telos-unsafe-pr7-composed-wallet-build-v1",
    "release_status": "HOLD",
    "source_commit": run("git", "rev-parse", "HEAD"),
    "source_tree": run("git", "rev-parse", "HEAD^{tree}"),
    "pr7_circuit_tree": run("git", "rev-parse", "HEAD:packages/libzeropool-pr7"),
    "wasm_crate_lock_sha256": digest(root / "packages/libzkbob-rs-wasm/Cargo.lock"),
    "yarn_lock_sha256": digest(root / "yarn.lock"),
    "build_script_sha256": digest(root / ".github/scripts/unsafe-pr7-composed-wallet-build.sh"),
    "rust_single_core": run("rustc", "+1.94.0", "--version"),
    "rust_multi_core": run("rustc", "+nightly-2026-05-17", "--version"),
    "wasm_bindgen_cli": run(str(bindgen), "--version"),
    "node": run("node", "--version"),
    "yarn": run("yarn", "--version"),
    "outputs_sha256": outputs,
    "qualified_ceremony": False,
    "pr7_prover_wired": False,
    "production_release_approved": False,
}
path = evidence / "manifest.json"
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
sha = digest(path)
(evidence / "SHA256SUMS").write_text(f"{sha}  manifest.json\n")
print(f"PASS: sealed build-only manifest for {len(outputs)} files; release HOLD")
PY
(cd "$EVIDENCE_DIR" && sha256sum --check SHA256SUMS)
