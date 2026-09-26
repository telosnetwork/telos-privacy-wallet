# WTLOS PR7 deposit adapter — local draft, HOLD

This is an opt-in Rust package for the fresh WTLOS-only V1 pool. It has no
WASM/JS export, wallet dispatch, relayer submission, RPC call, or deployed
configuration. The existing wallet's `libzkbob-rs` and its embedded
`libzeropool-zkbob` 1.4.0 history APIs remain unchanged.

The adjacent `packages/libzeropool-pr7` directory is an **unmodified 77-file
Git archive** of Telos Privacy circuits tree
`7a22196e1d4a791b452a6140bdfa915298f3f1da`. The local commit used for the
archive is `78b50d55ece7d60aa6aeb536b2b0e78739bba5ac`; a prior GitHub
readback recorded published PR #7 head
`2cf3102d02ab1e9efe23090e3541e8f09cece97c` with the same tree. The
adapter's locked dependency graph records the transitive Git revisions. We
used a vendored exact tree because this machine cannot currently authenticate
Git access to the Telos repository; no PR7 source file was edited. The
source-matched transfer identity is
`01ae02544199f79fcc21e2ddfd1f3bb1a35d680979cceec59e764fb3671be2b0`
with R1CS SHA-256
`6051176b4238978fc60d214db4b2755762b54b090ae4300e88b3e7371c27ce37`.

`finalize_deposit` accepts a **PR7-native witness** from a future wallet
builder. It checks the nonzero 24-bit pool ID, positive signed deposit delta,
zero output notes, and output commitment; encrypts the output account using
PR7's cipher and OS randomness; inserts `TPD1 || proxy` after the V1 item
count; builds the eight-byte-fee memo; reduces `keccak256(exact memo)` into the
field; and only then signs PR7's Poseidon hash over input hashes, output
commitment, memo field, and pool ID. `prove_deposit_with_unchecked_key` calls the **PR7**
`c_transfer` prover on those finalized values. PR21's WTLOS-only contract
hashes those same memo bytes and requires the embedded proxy address to equal
its own address. `amount` and `fee` are pool units; the contract converts the
net delta plus fee (equal to `amount`) to WTLOS base units at `10^9` base
units per pool unit.

Run from the wallet worktree:

```sh
CARGO_TARGET_DIR=/private/tmp/telos-pr7-tree-guard-20260925/target \
  CARGO_INCREMENTAL=0 cargo test --offline --locked \
  --manifest-path packages/wtlos-pr7-proof/Cargo.toml --lib
```

Ten tests pass. The strongest test constructs a synthetic initial deposit,
finalizes it, and checks its full PR7 transfer relation using `DebugCS`.
Other tests check exact memo layout, signature sensitivity to memo/pool
changes, and reject inconsistent fields. **No SNARK proof was generated, no
proving key was qualified, and no real wallet deposit was constructed.**

Before this can be a production client, a source-matched state/witness builder
must replace the 1.4.0 transfer construction for this pool while retaining the
old history route. The prover must load a final, independently qualified PR7
key and check its identity; a matching tree-update proof, EVM deposit-spender
signature, exact custom calldata serialization, relayer parser/domain checks,
WTLOS denomination and pool configuration, and full offline integration
vectors are still required. The proof entrypoint's argument is an unchecked
`Parameters` object today, so this function must not be wired to a live
wallet. Production release remains **HOLD / NO-GO**.
