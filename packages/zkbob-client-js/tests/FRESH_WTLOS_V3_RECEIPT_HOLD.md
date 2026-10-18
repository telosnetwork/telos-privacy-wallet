# Fresh WTLOS v3 receipt binder — HOLD

`fresh-wtlos-v3-receipt.ts` is an isolated source-only check for the exact r12
`Message(uint256,bytes32,bytes)` event emitted by a successful `transact()`.
It reparses the custom calldata, requires a matching successful transaction
and receipt, exactly one matching pool Message log, a canonical ABI bytes
payload identical to the calldata message, post-transaction event index equal
to the supplied pre-transaction current index plus 128, and the contract's
rolling hash `keccak256(priorHash || keccak256(message))`. It also calls the
separate helper that reconstructs both verifier public-input arrays.

The synthetic test's Keccak answers were independently calculated with
`cast keccak`; its callback recognizes only the fixture byte strings. This
test checks byte selection and composition, not a real wallet hash provider.

This binder authenticates nothing by itself. The caller must obtain the
transaction, receipt, logs, chain ID, prior all-messages hash, historical and
current roots from an authenticated and finality-aware source at the exact
pre-transaction state. Reading the preceding block is insufficient when
earlier pool transactions occur in the same block. The caller must also supply
a correct Keccak-256 implementation. A matching response from one RPC is not
a cryptographic proof of inclusion or of state authenticity.

No running wallet path imports this module. It does not verify either ZK
proof, derive an accepted witness, validate the deposit EIP-712 signature,
decrypt guarded ciphertext, verify WTLOS transfers, or establish production
deployment identity. The selected r12 candidate remains production HOLD.
