# Fresh WTLOS v3 intent helper — source-only HOLD

`fresh-wtlos-v3-intent.ts` builds the exact EIP-712 type/domain/message of the
selected WTLOS candidate at contracts commit
`042a3cbf8dc27d4ca57c614e08e4bcd811e30159` (production `src` tree
`1789d4ced03bd7fdc7101cfb066723aea1768a19`). It rejects malformed or
out-of-range fields and emits the exact `memo || uint64 deadline (big endian) ||
64-byte EIP-2098 signature` suffix. Its transaction-data adapter uses the
wasm-generated proof public fields directly, checks the packed pool ID and
checks that the public memo field equals Keccak(raw memo) modulo BN254 Fr.
The legacy `ApproveSigner` is untouched.
The copied synthetic vector is byte-identical to
`formal/wtlos-deposit-auth-v3/deposit-intent-vector.json` at that contracts
commit (both SHA-256
`5cd1a83a35bcd98af97e5f0ccf7f36d119d0c87e33c92995c834ca6a960e68c0`).
Run the bounded test with:

```sh
node --experimental-strip-types packages/zkbob-client-js/tests/fresh-wtlos-v3-intent.mjs
```

This helper is not wired into the wallet. Its Keccak callback must hash the
exact raw memo bytes; the synthetic test checks the call boundary and the
contract's independently checked vector, but does not execute a browser
wallet, sign, prove, submit, or authenticate the relayer. The wallet must
still select the fresh pool, build the statement from final proof inputs,
verify the recovered signer, pass the signed deadline/operator through the
queue and relayer, and use qualified guarded proving artifacts. The release
remains HOLD.

The separate `fresh-wtlos-v3-deposit.ts` source bridge preflights the type-0
calldata public inputs against that signed transfer statement and the supplied
tree statement before requesting a signature. It copies the route, roots,
proof bytes and transaction fields before any asynchronous wallet callback,
then assembles the final call from the same snapshot and checks its public
inputs again. Every later memo hash must equal the full 256-bit digest signed
in EIP-712, even if a different digest reduces to the same circuit field.
The two proof byte arrays remain opaque; a supplied tree public
statement and roots are not authenticated by this helper. It is still not
imported into the running wallet, and the isolated test uses a synthetic signer
and known memo digest. No real proving, signing, relaying or broadcast ran.
