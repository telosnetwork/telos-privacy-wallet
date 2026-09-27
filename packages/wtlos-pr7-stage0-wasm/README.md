# PR7 Stage 0 browser adapter (test only)

This separate `wasm-bindgen` crate exposes `UnsafeStage0Params.fromBinary`,
`sourceTree`, `parameterSha256`, and `unsafeStage0Tx(kind, witness)` for
PR7-native deposit, funded transfer, and withdrawal witnesses. It uses the
real `wtlos-pr7-proof` finalizer and Groth16 prover. The constructor accepts
only a source-matched Groth16 key converted offline from the exact sealed
**unqualified Stage 0 transfer** MPC file. The converted key SHA-256 is
`44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1`.
It checks SHA-256 over all bytes,
parses with point checks, and rejects trailing bytes. The raw MPC transcript
cannot be loaded directly by `Parameters::read`.
The proof output is public-only and carries the source-tree and parameter
identity. Amounts and fees are canonical decimal strings; addresses are
20-byte arrays. Secret witness data never appears in the result.

The production wallet worker does not import this crate. It requires a
different PR7-specific browser module API and remains fail-closed. There is
no qualified ceremony, production browser witness builder, or end-to-end
browser proof validation here. A prior exact-head hosted build and local
Chromium key-parser control produced test-only JS/WASM evidence. The separate
`browser-test/prove-stage0.mjs` diagnostic uses a sealed synthetic deposit
witness; that earlier WASM trapped in Bellman CE's multicore waiter during
proof construction, before any proof could be verified.

The isolated browser build uses a local Phase 2 dependency variant to avoid
the native-only `rust-crypto` and `rustc-serialize` packages on
`wasm32-unknown-unknown`. The PR7 circuit package itself retains the exact
`7a22196e1d4a791b452a6140bdfa915298f3f1da` Git tree and its ceremony
source lock. The variant copies upstream Phase 2 commit
`0d286cc94af78e96d3d1184b0e38246714afa838`; its only upstream file
change is `Cargo.toml`, moving `rust-crypto` to non-WASM targets and
resolving the same pinned Bellman Git source instead of an unavailable sibling
path. `ci/phase2-origin.json` pins all 27 upstream files, and
`ci/verify_source.py` checks every copied file, the distinct vendor tree,
the lockfile override, and the unchanged PR7 tree. This dependency
substitution still needs a hosted WASM build and a relation/key compatibility
check; identical PR7 source bytes alone do not prove either.

The Phase 2 variant now enables Bellman CE's `multicore` feature only for
non-WASM targets, preserving the native feature graph while allowing the
browser build to use Bellman's single-core implementation. This change is a
test-only candidate prompted by the trapped browser prover. It requires a new
exact-head hosted build, isolated browser proof, and source-matched Stage 0 VK
verification before anyone can claim that the browser proof path works.

The browser and standalone proof manifests request only PR7's
`in3out127` circuit feature, excluding the native setup CLI and its
`clap-v3` dependency from the WASM build. The Stage 0 manifest explicitly
enables Fawkes's Groth16 backend and WASM entropy features. PR7's locked
Fawkes default also retains Groth16 for the standalone proof crate.
The source guard pins the exact SHA-256 of both Cargo lockfiles.

The opt-in `convert_exact_stage0_for_browser` test uses the exact sealed MPC
file and VK JSON, replays PR7 transfer gate compression, and writes the
converted key at a new path. Its output was independently hashed and the
digest above was pinned. The opt-in `parse_exact_converted_browser_key_and_reject_mutation`
test checks the converted file and two changed-byte controls.

The `.github/workflows/unsafe-pr7-stage0-browser.yml`
`UNSAFE_STAGE0_NO_GO` candidate has two separate events. A draft PR that
changes this fixture runs a **build-only** job: it compiles the isolated WASM
adapter and seals JS/WASM hashes without fetching a key, opening Chromium,
or claiming a browser key parse. Manual dispatch remains a separate path;
GitHub requires its workflow file on the default branch before that event can
run. The workflow pins Rust 1.94.0,
`wasm32-unknown-unknown`, wasm-bindgen CLI 0.2.118, Playwright 1.56.1,
the action commit IDs and this crate's Cargo lock. Manual dispatch requires
an HTTPS URL for the exact unqualified converted Stage 0 key and fails when it is
missing or its size/SHA-256 differs. The Chromium fixture loads generated
browser glue and WASM, parses that exact key, rejects empty and changed-byte
keys, and rejects an unsupported transaction kind. The evidence manifest
binds the source commit/tree, lock, JS, WASM and browser result hashes. It
never uploads the key.

This remains a **test-only browser fixture**. The synthetic PR7 witness
diagnostic is not a production witness builder, and no browser proof or
browser proof verification has passed. The prior exact-head hosted build
sealed JS/WASM bytes and a local parser control accepted the exact Stage 0
key; a subsequent local proof attempt trapped. This single-core candidate
has not yet had its own hosted build. The source pin retains
`browser_wasm_built: false` as a release HOLD flag. Publishing a draft PR
does not merge it: a merge to
`main` would trigger the repository's existing production and staging wallet
deploy workflows, and needs separate approval. A qualified ceremony, final parameter/VK binding,
independent review and wallet dispatch remain necessary for production.
