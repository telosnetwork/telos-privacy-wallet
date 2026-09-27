# WTLOS PR7 proof adapter — offline draft, HOLD

This opt-in Rust package finalizes PR7-native witnesses for a fresh WTLOS-only
V1 pool. It handles deposit, funded private transfer, and WTLOS withdrawal
memos. It is separate from the wallet's 1.4.0 history code and is **not**
connected to a wallet, relayer, RPC, or deployed pool.

The isolated `tests/legacy_wallet_bridge.rs` experiment now constructs a
deposit with the actual legacy `libzkbob-rs::UserAccount` and in-memory wallet
state. It translates the serialized public/secret witness into the separate
PR7 type universe, derives the signing scalar only inside the Rust test,
recomputes PR7's canonical-eta/physical-position nullifier, and lets this
adapter reencrypt the V1 memo and sign the memo-and-pool-bound PR7 hash. The
normal test checks this conversion and wrong-nullifier rejection without a
proving key. Its ignored, opt-in test accepts only the exact zero-contribution
Stage 0 converted key digest, constructs a Groth16 deposit proof and verifies
it with that key's VK; changed public inputs must reject. The production
`UserAccount` and wallet worker do not call this bridge. Neither a funded
transfer nor a withdrawal has been generated from actual wallet state yet.

The self-contained memo-domain codec in `src/domain.rs` is byte-for-byte
vendored from `packages/libzkbob-rs/src/wtlos_v1_domain.rs` at commit
`e6aa95a69e6246028f084c46f5258798bf7533ec` (SHA-256
`b4a9cfc6c3c46231231d76028bdcfb290504d09f83617a3acfbf2d2df31e1918`).
The Stage 0 source check pins this copy and the proof package's source pin.
The isolated package therefore compiles without adding wallet runtime files
to this test-only branch.

`packages/libzeropool-pr7` is the exact unmodified circuit source tree
`7a22196e1d4a791b452a6140bdfa915298f3f1da` from draft circuits PR #7.
The adapter finalizes the full `TPD1 || proxy` memo, hashes its exact calldata
bytes to the PR7 field element, and signs the PR7 transaction hash only after
memo and pool ID are fixed. Private transfer outputs may include a contiguous
prefix of funded notes; their recipient points are validated before encryption.
Withdrawal leaves the native conversion field zero and puts the WTLOS recipient
at the V1 fixed-field offset. The PR7 circuit remains responsible for
account/note membership, ownership, balances, and tree paths.

The `prove_*_with_unchecked_key` entry points intentionally accept an
unauthenticated prover object and are for offline work only. The ignored
`unsafe_current_stagezero_funded_flow_proof` test decrypts a previously sealed
first deposit memo, reconstructs its funded account and commitment, then
generates real transfer and withdrawal Groth16 proofs plus tree append proofs.
It checks both Stage 0 files by SHA-256 and both parsed verifier keys against
the pinned JSON, verifies each proof, and writes public-only JSON. The local
PR21 harness accepts the three-operation proof sequence and rejects changed
memo/proof bytes, nullifier replays, and same-ID second-proxy reuse.

Run ordinary tests with:

```sh
CARGO_TARGET_DIR=/private/tmp/telos-pr7-tree-guard-20260925/target \
  CARGO_INCREMENTAL=0 cargo test --offline --locked \
  --manifest-path packages/wtlos-pr7-proof/Cargo.toml
```

With the exact, independently sealed **unqualified** converted transfer key,
run the wallet-builder proof experiment explicitly:

```sh
UNSAFE_PR7_CONVERTED_KEY=/path/to/UNSAFE_stage0_converted_transfer.bin \
  cargo test --offline --locked \
  --manifest-path packages/wtlos-pr7-proof/Cargo.toml \
  --test legacy_wallet_bridge -- --ignored --nocapture
```

The ignored proof test additionally requires the sealed first-deposit proof,
both exact Stage 0 MPC files and VK JSON paths, and a **new** output path via
`UNSAFE_PR7_FIRST_DEPOSIT_PROOF`, `UNSAFE_PR7_STAGE0_TRANSFER`,
`UNSAFE_PR7_STAGE0_TRANSFER_VK`, `UNSAFE_PR7_STAGE0_TREE`,
`UNSAFE_PR7_STAGE0_TREE_VK`, and `UNSAFE_PR7_FUNDED_FLOW_OUT`. Run it with
`cargo test ... unsafe_current_stagezero_funded_flow_proof -- --ignored --nocapture`.

For the independent nonzero-fee rehearsal, set
`UNSAFE_PR7_NONZERO_FEE_FLOW_OUT` to a new output path instead of
`UNSAFE_PR7_FUNDED_FLOW_OUT`. That opt-in vector charges one pool unit in the
private transfer and two in the sender withdrawal. It keeps a 500,000,000-unit
recipient note and checks recipient-key decryption, both DebugCS relations,
and both Groth16 transfer/tree proofs against the pinned Stage 0 keys.
The resulting JSON is unsafe test material, never a production proof package.

The separate ignored recipient-note test also accepts
`UNSAFE_PR7_NONZERO_FEE_PROOFS` with the exact sealed three-step fee-proof
sample, plus a new `UNSAFE_PR7_FEE_RECIPIENT_SPEND_OUT` path. It decrypts
the 500,000,000-unit note at physical position 129 with the recipient key,
reconstructs the post-withdrawal root, and generates a fresh zero-fee
recipient withdrawal plus tree-update proof. The first three proofs are
pinned inputs in this follow-on, not regenerated by that test.

Stage 0 has **zero independent Phase 2 contributions**. This package does not
qualify the keys, bind a final deployed verifier, supply a live wallet route,
or establish whole-system formal verification. Production release is HOLD.
