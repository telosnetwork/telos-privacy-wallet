# WTLOS PR7 proof adapter — offline draft, HOLD

This opt-in Rust package finalizes PR7-native witnesses for a fresh WTLOS-only
V1 pool. It handles deposit, funded private transfer, and WTLOS withdrawal
memos. It is separate from the wallet's 1.4.0 history code and is **not**
connected to a wallet, relayer, RPC, or deployed pool.

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
  --manifest-path packages/wtlos-pr7-proof/Cargo.toml --lib
```

The ignored proof test additionally requires the sealed first-deposit proof,
both exact Stage 0 MPC files and VK JSON paths, and a **new** output path via
`UNSAFE_PR7_FIRST_DEPOSIT_PROOF`, `UNSAFE_PR7_STAGE0_TRANSFER`,
`UNSAFE_PR7_STAGE0_TRANSFER_VK`, `UNSAFE_PR7_STAGE0_TREE`,
`UNSAFE_PR7_STAGE0_TREE_VK`, and `UNSAFE_PR7_FUNDED_FLOW_OUT`. Run it with
`cargo test ... unsafe_current_stagezero_funded_flow_proof -- --ignored --nocapture`.

Stage 0 has **zero independent Phase 2 contributions**. This package does not
qualify the keys, bind a final deployed verifier, supply a live wallet route,
or establish whole-system formal verification. Production release is HOLD.
