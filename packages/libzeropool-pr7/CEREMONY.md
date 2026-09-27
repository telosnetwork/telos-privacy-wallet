# Transfer and tree-update Phase 2 contributor candidate

This is an isolated candidate for the repaired transfer and tree-update relations. It is not an approved ceremony, a proving key, or a production release. Both circuit sources and serialized R1CS are pinned by `formal/ceremony-source-lock.json`; changing this CLI changes the compiled **source identities** even if the R1CS digests stay the same. Reapprove both identities and review the tool before any real participant uses it. Each public radix must have separate Phase 1 provenance and validation. A changed circuit relation requires fresh Phase 2 initialization and contributions.

This revision rejects an identity spending public key in the transfer circuit: otherwise the identity key and zero signature satisfy the old full transfer relation for different public memo and pool-ID values. It also rejects an empty-block tree append and directly requires the public tree root to change on every accepted append. The old tree relation admitted an empty-block proof with the same root before and after while the pool advanced its operation index. The old PR7 transfer and tree-update stage zeros, keys, verifiers, identities, and source-bound checkers cannot be reused. The regression tests cover these specific witnesses; they are not whole-circuit or whole-system proofs.

The old `setup`, `contribute`, `generate-vk`, and `generate-verifier` handlers stay disabled. The new `initialize-phase2` checks the compiled identity of the selected circuit, exact public radix digest, size, points and subgroup; snapshots it privately; calls the pinned Phase 2 initializer; verifies the zero-contribution parameters against the same circuit and radix; and writes a new 0700 stage directory. Transfer uses radix18; tree update uses radix15. **Stage zero is unsafe toxic-waste material**, not a ceremony result. The `contribute-phase2` command requires the independently approved SHA-256 of its predecessor, validates the predecessor's complete encoding and byte digest, checks its receipt binds the same circuit/radix chain, reads 32–4096 bytes of supplemental entropy from preopened descriptor 3 or higher, mixes it with 256 bits from the OS CSPRNG under a domain-separated SHA-256, and seeds the pinned ChaCha20 RNG using explicit little-endian words. It verifies the in-memory algebraic transition and again verifies the serialized output before issuing a receipt. The legacy library prints no progress with the zero interval used here. Entropy is never accepted in an argument or environment variable and is never logged. Buffers and RNG are scrubbed best effort; this does not prove the entropy source, destruction, host integrity, or lack of memory copies.

Each stage directory must be new. The CLI opens its parent directory without following symlinks, creates the child with `mkdirat`, writes stage files with exclusive `openat`, syncs them and sets them read-only. A failed operation can leave an incomplete private directory without a receipt; quarantine it. Ordinary filesystem permissions and read-only mode are not WORM storage and do not protect against the same user account or a compromised host. Publish complete stages to an independently controlled immutable archive with recorded SHA-256 digests. A participant should work offline on a trusted machine and remove all local toxic-waste seed material under their own documented procedure.

Command shape for transfer after independent source/radix approval (replace pins and paths with actual coordinator-approved values). For tree update, use `--circuit tree_update`, its separately approved identity and radix15 digest, and separate stage directories; never mix stages between circuits:

```sh
cargo build --offline --locked --no-default-features --features cli_libzeropool_setup,in3out127 --bin libzeropool-setup
./target/debug/libzeropool-setup initialize-phase2 --circuit transfer \
  --radix /approved/radix --expected-radix-sha256 RADIX_SHA256 \
  --expected-identity IDENTITY_SHA256 --stage-directory /private/stage-0000
./target/debug/libzeropool-setup contribute-phase2 --circuit transfer \
  --before /private/stage-0000/mpc-params.bin \
  --before-receipt /private/stage-0000/stage-receipt.json \
  --expected-before-sha256 APPROVED_STAGE_0000_SHA256 \
  --expected-identity IDENTITY_SHA256 --expected-radix-sha256 RADIX_SHA256 \
  --stage-index 1 --entropy-fd 3 --stage-directory /private/stage-0001 \
  3< /private/participant-entropy.bin
./target/debug/libzeropool-setup verify-transition --circuit transfer \
  --before /private/stage-0000/mpc-params.bin \
  --after /private/stage-0001/mpc-params.bin \
  --after-receipt /private/stage-0001/stage-receipt.json \
  --expected-before-sha256 APPROVED_STAGE_0000_SHA256 \
  --expected-after-sha256 APPROVED_STAGE_0001_SHA256 \
  --expected-identity IDENTITY_SHA256 --expected-radix-sha256 RADIX_SHA256 --stage-index 1
```

The private input file in the example must be generated and protected by the participant. Never pass its contents in a shell command, chat, log, or ticket. A FIFO or inherited pipe may be used instead if its writer closes the descriptor at EOF. The program blocks until EOF and rejects undersized or oversized input. At least two genuinely independent participants should each run one contribution on their own trusted machine. The `participant-statement.json` file is an **unsigned template** with the public circuit/radix/byte/contribution hashes. A participant must add their real identity and entropy-destruction attestation to a separate public copy, then sign the exact bytes using an independently reviewed signing process. The coordinator must authenticate the keys and identities, check independence, signature bytes and every adjacent stage, and archive signed statements out of band. This candidate CLI does not verify those signatures and must not treat unsigned templates as identity evidence.

The `verify-ceremony` command independently pins each circuit's final transcript SHA-256, circuit identity, radix SHA-256 and ordered contribution hashes, performs complete source-bound Phase 2 verification, and can derive final artifacts into a new directory only after success. A contributor receipt or single-transition result does not replace that final check. No real independent stages, signed statements, final transcript, or verifier artifacts are included in this candidate. External security review, matched runtime/proof tests, client integration, and deployment authorization remain separate release gates.
