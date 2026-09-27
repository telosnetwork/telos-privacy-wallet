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
no qualified ceremony, generated browser WASM, source-to-WASM artifact seal,
browser witness builder, or end-to-end browser proof validation here.

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

This is a **key-parser/browser-build fixture, not a browser proof fixture**:
there is no PR7-native browser witness serialization fixture, generated
browser proof, or browser proof verification yet. Neither event has run on a
hosted runner from this isolated worktree, so no JS/WASM byte hashes exist
yet. The source pin deliberately retains `browser_wasm_built: false` until a
hosted run is inspected. Publishing a draft PR does not merge it: a merge to
`main` would trigger the repository's existing production and staging wallet
deploy workflows, and needs separate approval. A qualified ceremony, final parameter/VK binding,
independent review and wallet dispatch remain necessary for production.
