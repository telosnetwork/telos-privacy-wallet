# Fresh WTLOS v3 calldata assembly and decoder — HOLD

The isolated `fresh-wtlos-v3-calldata.ts` parses the exact r12 `transact()`
custom byte layout after a caller supplies authenticated chain-40 transaction
destination and a trusted `(pool ID, proxy, version)` route. It rejects bad
selector, noncanonical public field values, unsupported type, inconsistent
length or tail, malformed memo envelope and invalid transaction economics.
It returns separate `transferTokenDelta` (the signed circuit delta) and
`poolTokenFlowUnits` (delta plus fee, positive into the pool and negative out,
in 1e-9 WTLOS units). Neither value is WTLOS wei or a display amount without
the pool's denominator and authenticated token transfer evidence.
For deposits it returns the eight-byte deadline and 64-byte compact signature
without authenticating ECDSA. For withdrawals it rejects nonzero native amount
and zero recipient through the memo adapter. A separate helper compares the
full event message with the decoded calldata message and requires a matching
emitter. Synthetic tests cover all three transaction types and mutations.
The isolated TypeScript source passes strict no-emit checking with the
package-compatible `.js` relative import; the Node test strips types into a
temporary ESM package to exercise that emitted import shape.

`assembleFreshWTLOSV3Calldata` now builds the same custom layout from final
public fields, two opaque 256-byte proof arrays, the already-finalized raw
memo, and a deposit-only deadline/compact-signature tail. It bounds signed
integer widths, canonical public fields, reachable aligned transfer indices,
proof and signature byte lengths, and rejects extra tails. It reparses its own
result to enforce the memo domain, type and economics checks. Synthetic tests
compare its bytes to the independently laid-out fixed calldata fixture for
deposit, transfer and withdrawal and reject malformed boundaries. The
assembler neither generates nor verifies either proof or signature; the raw
memo must have been bound to the guarded owner witness before it is supplied.

The separate `freshWTLOSV3VerifierInputs` helper reparses the raw calldata and
constructs the exact five transfer and three tree verifier inputs. It requires
two explicitly indexed, nonzero canonical roots from the authenticated pool
**pre-transaction state**: the stored historical root selected by
`transferIndex`, and the current root at the prior transaction count times
128. A caller-provided Keccak-256 function hashes the full raw memo and its
digest is reduced modulo BN254 Fr, as in `Parameters.sol`. The helper rejects
misaligned, mismatched or out-of-order indices, current indices beyond the
uint32 transaction count's last successful pre-state, and noncanonical roots. Its
synthetic tests use independently computed raw-memo Keccak fixtures and a
second operation with distinct historical and current roots.

The caller must authenticate the RPC chain, destination, transaction and
receipt, successful receipt status, log index and emitter, plus the exact
pre-transaction storage state and Keccak implementation. Neither root is
carried in calldata; supplying plausible roots does not authenticate them.
This helper does not
verify either proof, the deposit signature, decrypted note contents, token
transfers, or the actual guarded wasm parser. No running wallet path imports
this module. The selected guarded circuit source remains unpublished and the
fresh pool remains production HOLD.
