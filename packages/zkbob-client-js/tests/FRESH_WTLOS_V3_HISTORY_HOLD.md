# Fresh WTLOS v3 ordered history replay — HOLD

`FreshWTLOSV3HistoryReplay` starts from the exact r12 empty-root and zero
message-hash constants. Given a complete, canonical sequence of successful
fresh-pool transactions and receipts, it derives the historical root selected
by each calldata `transferIndex` and the current pre-update root from earlier
accepted `nextRoot` values. Every step uses the isolated receipt binder to
check transaction/receipt/log identity, the event index and rolling message
hash. It updates its own roots and hash only after that step passes. A final
checkpoint comparison can detect a truncated or divergent sequence **if** the
expected checkpoint was obtained independently from trusted chain state.
Transactions in the same block must also agree on their block hash and have
strictly increasing transaction indices.
`advance()` rejects callback reentrancy and snapshots the supplied records
before invoking the Keccak callback. A rejected validation step leaves the
replay checkpoint unchanged. The callback itself must still be a trusted,
correct Keccak-256 implementation without unrelated side effects.

The synthetic test covers a deposit followed by a private transfer in the
same block. The second transfer uses the initial historical root while its
tree proof uses the first transaction's current root. A corrupted second
receipt leaves the replay state unchanged. Missing, repeated, and out-of-order
transactions are rejected. Reentrant and record-mutating hash callbacks are
covered by separate controls. The Keccak fixture answers were independently
calculated with `cast keccak`; the test does not run a real wallet hash provider.

The replay cannot establish that RPC records are genuine, canonical, final,
complete from initialization, or emitted by the selected deployed runtime.
The caller must independently authenticate the deployment/initialization
anchor, every transaction and receipt, and the final checkpoint. A normal
prior-block state read is not enough when earlier pool transactions share a
block. The replay does not verify a ZK proof, an accepted witness, token
movement, guarded decryption or production readiness. No running wallet path
imports it; the candidate remains HOLD.
