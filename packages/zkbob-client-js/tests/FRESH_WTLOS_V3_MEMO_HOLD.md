# Fresh WTLOS v3 memo adapter — HOLD

The isolated `fresh-wtlos-v3-memo.ts` module unwraps the r12 TPD1/proxy
message only when a caller supplies trusted chain-40, pool-ID and proxy
configuration. Its synthetic tests compare the event/subgraph message shape
with the decoded V1 calldata raw memo and reject malformed envelopes.
The message does not contain a pool ID: the future caller must bind the
chain-40 pool ID, proxy, version and transaction source through trusted
configuration before using this adapter. The raw extractor returns the fee
and withdrawal recipient but does not authenticate them against the public
delta or receipt; the caller must perform those comparisons.

No running wallet path imports or selects this module. It does not call the
guarded native decryptor, build a witness or proof, validate any published
parameters, or establish that the current wasm parser is compatible. The
guarded circuit source and local Rust boundary remain unpublished. Production
is HOLD.
