import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const dir = mkdtempSync(join(tmpdir(), 'fresh-wtlos-v3-deposit-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
writeFileSync(join(dir, 'package.json'), '{"type":"module"}\n');
mkdirSync(join(dir, 'src', 'networks', 'evm'), { recursive: true });
mkdirSync(join(dir, 'src', 'signers'), { recursive: true });
for (const name of ['memo', 'calldata', 'deposit']) {
  const source = readFileSync(new URL(`../src/networks/evm/fresh-wtlos-v3-${name}.ts`, import.meta.url), 'utf8');
  writeFileSync(join(dir, 'src', 'networks', 'evm', `fresh-wtlos-v3-${name}.js`),
    stripTypeScriptTypes(source));
}
const intentSource = readFileSync(new URL('../src/signers/fresh-wtlos-v3-intent.ts', import.meta.url), 'utf8');
writeFileSync(join(dir, 'src', 'signers', 'fresh-wtlos-v3-intent.js'), stripTypeScriptTypes(intentSource));
const { assembleSignedFreshWTLOSV3Deposit } = await import(pathToFileURL(
  join(dir, 'src', 'networks', 'evm', 'fresh-wtlos-v3-deposit.js')).href);
const { parseFreshWTLOSV3Calldata } = await import(pathToFileURL(
  join(dir, 'src', 'networks', 'evm', 'fresh-wtlos-v3-calldata.js')).href);

const proxy = `0x${'11'.repeat(20)}`;
const depositor = `0x${'44'.repeat(20)}`;
const operator = `0x${'22'.repeat(20)}`;
const context = { format: 'fresh-wtlos-v3', chainId: 40, poolId: 7, poolProxy: proxy };
const roots = { historical: { index: 0n, root: 101n }, current: { index: 128n, root: 102n } };
const treePublic = [102n, 3n, 2n];
const inner = Buffer.alloc(202);
inner.writeUInt32LE(1, 0);
inner[4] = 0xaa;
inner[201] = 0xbb;
const rawMemo = `0x${Buffer.concat([
  Buffer.from('0000000000000002', 'hex'), Buffer.alloc(4), Buffer.from('TPD1'),
  Buffer.from(proxy.slice(2), 'hex'), Buffer.from('00ca', 'hex'), inner,
]).toString('hex')}`;
// Independently calculated with Foundry cast keccak over this exact raw memo.
const memoDigest = '0x3aab3841e1fd09792994c9dfbcfd7362da89bb8fed44a888091b330b44a68888';
const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const tx = { public: {
  root: 101n, nullifier: 1n, out_commit: 2n,
  delta: (7n << 224n) + 10n, memo: BigInt(memoDigest) % field,
}, memo: rawMemo };
const proofs = {
  transferIndex: 0n, energyAmount: 0n, transferTokenDelta: 10n,
  transferProof: '00'.repeat(256), nextRoot: 3n, treeProof: '00'.repeat(256),
};
let signCalls = 0;
const signature = `0x${'00'.repeat(31)}01${'00'.repeat(31)}01`;
const backend = {
  getChainId: async () => 40,
  toCompactSignature: () => signature,
  recoverSignerTypedData: async () => depositor,
};
const keccak = value => {
  assert.equal(value.toLowerCase(), rawMemo);
  return memoDigest;
};
const sign = async request => {
  signCalls++;
  assert.equal(request.type, 1);
  assert.equal(request.data.message.root, '101');
  assert.equal(request.data.message.nullifier, '1');
  assert.equal(request.data.message.packedDeltaAndPoolId, `0x${tx.public.delta.toString(16).padStart(64, '0')}`);
  assert.equal(request.data.message.memoDataHash, memoDigest);
  return signature;
};
const args = [context, roots, tx, treePublic, proofs,
  depositor, 2000000000n, operator, keccak, backend, sign, () => 1000];
const result = await assembleSignedFreshWTLOSV3Deposit(...args);
assert.equal(signCalls, 1);
assert.deepEqual(result.verifierInputs.transfer,
  [101n, 1n, 2n, tx.public.delta, tx.public.memo]);
assert.deepEqual(result.verifierInputs.tree, treePublic);
const parsed = parseFreshWTLOSV3Calldata(context, { chainId: 40, to: proxy }, result.calldata);
assert.equal(parsed.rawMemo, rawMemo.slice(2));
assert.equal(parsed.deadline, 2000000000n);
assert.equal(parsed.compactSignature, signature.slice(2));
assert.equal(result.signedIntent.typedData.message.operator, operator);

// Each mismatched prover/pre-state statement must fail before any signature request.
const rejectBeforeSigning = async (index, replacement) => {
  const before = signCalls;
  const changed = [...args];
  changed[index] = replacement;
  await assert.rejects(assembleSignedFreshWTLOSV3Deposit(...changed));
  assert.equal(signCalls, before);
};
await rejectBeforeSigning(2, { ...tx, public: { ...tx.public, root: 100n } });
await rejectBeforeSigning(2, { ...tx, public: { ...tx.public, delta: tx.public.delta + 1n } });
await rejectBeforeSigning(2, { ...tx, public: { ...tx.public, memo: tx.public.memo + 1n } });
await rejectBeforeSigning(3, [102n, 4n, 2n]);
await rejectBeforeSigning(4, { ...proofs, transferIndex: 128n });
await rejectBeforeSigning(4, { ...proofs, transferTokenDelta: 11n });
await rejectBeforeSigning(4, { ...proofs, nextRoot: 4n });
await rejectBeforeSigning(0, { ...context, poolId: 8 });
await rejectBeforeSigning(0, { ...context, chainId: 41 });

// Wallet callbacks cannot change the captured public fields or final call.
const mutableTx = { public: { ...tx.public }, memo: rawMemo };
const mutableFields = { ...proofs };
const mutableContext = { ...context };
const mutableRoots = { historical: { ...roots.historical }, current: { ...roots.current } };
const mutatingSign = async () => {
  mutableTx.public.nullifier = 99n;
  mutableTx.memo = '0x00';
  mutableFields.transferTokenDelta = 99n;
  mutableContext.poolId = 8;
  mutableRoots.historical.root = 99n;
  return signature;
};
const mutated = await assembleSignedFreshWTLOSV3Deposit(mutableContext, mutableRoots,
  mutableTx, treePublic, mutableFields, depositor, 2000000000n, operator,
  keccak, backend, mutatingSign, () => 1000);
assert.equal(mutated.calldata, result.calldata);

// A hash provider changing its answer after signing cannot produce calldata.
let digestCalls = 0;
await assert.rejects(assembleSignedFreshWTLOSV3Deposit(
  context, roots, tx, treePublic, proofs, depositor, 2000000000n, operator,
  value => {
    assert.equal(value.toLowerCase(), rawMemo);
    digestCalls++;
    return digestCalls === 4 ? `0x${'11'.repeat(32)}` : memoDigest;
  }, backend, sign, () => 1000,
));
assert.equal(digestCalls, 4);

await assert.rejects(assembleSignedFreshWTLOSV3Deposit(...args.slice(0, 5),
  `0x${'55'.repeat(20)}`, ...args.slice(6)));
console.log('PASS_FRESH_WTLOS_V3_SIGNED_DEPOSIT_SOURCE_ONLY');
