import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// Strip types into a temporary ESM package so this test runs the same .js
// relative import that the wallet package's TypeScript build emits.
const testDir = mkdtempSync(join(tmpdir(), 'fresh-wtlos-v3-calldata-'));
process.on('exit', () => rmSync(testDir, { recursive: true, force: true }));
writeFileSync(join(testDir, 'package.json'), '{"type":"module"}\n');
for (const name of ['fresh-wtlos-v3-memo', 'fresh-wtlos-v3-calldata']) {
  const source = readFileSync(new URL(`../src/networks/evm/${name}.ts`, import.meta.url), 'utf8');
  writeFileSync(join(testDir, `${name}.js`), stripTypeScriptTypes(source));
}
const { freshWTLOSV3VerifierInputs, matchFreshWTLOSV3Event, parseFreshWTLOSV3Calldata } =
  await import(pathToFileURL(join(testDir, 'fresh-wtlos-v3-calldata.js')).href);

const proxy = '0x' + '11'.repeat(20);
const context = { format: 'fresh-wtlos-v3', chainId: 40, poolId: 7, poolProxy: proxy };
const source = { chainId: 40, to: proxy };
const emitter = { chainId: 40, emitter: proxy };
const hex = bytes => Buffer.from(bytes).toString('hex');
const be = (value, size) => {
  let n = BigInt(value);
  if (n < 0n) n += 1n << BigInt(size * 8);
  const bytes = Buffer.alloc(size);
  for (let i = size - 1; i >= 0; i--) { bytes[i] = Number(n & 255n); n >>= 8n; }
  assert.equal(n, 0n);
  return bytes;
};
const inner = Buffer.alloc(202);
inner.writeUInt32LE(1, 0);
inner[4] = 0xaa;
inner[201] = 0xbb;
const message = Buffer.concat([
  Buffer.alloc(4), Buffer.from('TPD1'), Buffer.from(proxy.slice(2), 'hex'),
  be(inner.length, 2), inner,
]);
const fee = 2n;
const recipient = Buffer.alloc(20, 0x22);
// Independently calculated with Foundry cast keccak over each raw memo.
const memoDigests = {
  '0000': '0x3aab3841e1fd09792994c9dfbcfd7362da89bb8fed44a888091b330b44a68888',
  '0001': '0x3aab3841e1fd09792994c9dfbcfd7362da89bb8fed44a888091b330b44a68888',
  '0002': '0x8063452e1a4e36ba8017572a632caee05816cb3c5ea5d3ce9b70d4ddaa07eaec',
};
const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function makeCalldata(txType, tokenAmount, suppliedMessage = message) {
  const rawMemo = Buffer.concat([
    be(fee, 8),
    ...(txType === '0002' ? [Buffer.alloc(8), recipient] : []),
    suppliedMessage,
  ]);
  const tail = txType === '0000'
    ? Buffer.concat([be(1000, 8), Buffer.alloc(64, 0x33)]) : Buffer.alloc(0);
  return Buffer.concat([
    Buffer.from('af989083', 'hex'),
    be(1, 32), be(2, 32), be(0, 6), be(0, 14), be(tokenAmount, 8),
    Buffer.alloc(256), be(3, 32), Buffer.alloc(256),
    Buffer.from(txType, 'hex'), be(rawMemo.length, 2), rawMemo, tail,
  ]);
}

const cases = [
  ['0000', 10n],
  ['0001', -fee],
  ['0002', -10n],
];
for (const [txType, tokenAmount] of cases) {
  const bytes = makeCalldata(txType, tokenAmount);
  const parsed = parseFreshWTLOSV3Calldata(context, source, `0x${hex(bytes)}`);
  assert.equal(parsed.chainId, 40);
  assert.equal(parsed.poolId, 7n);
  assert.equal(parsed.poolProxy, proxy);
  assert.equal(parsed.txType, txType);
  assert.equal(parsed.nullifier, 1n);
  assert.equal(parsed.outCommit, 2n);
  assert.equal(parsed.nextRoot, 3n);
  assert.equal(parsed.energyAmount, 0n);
  assert.equal(parsed.transferTokenDelta, tokenAmount);
  assert.equal(parsed.poolTokenFlowUnits, tokenAmount + fee);
  assert.equal(parsed.fee, fee);
  assert.equal(parsed.guardedMemo, hex(inner));
  assert.equal(parsed.eventMessage, hex(message));
  assert.equal(parsed.packedDeltaAndPoolId, (7n << 224n) + BigInt('0x' + hex(bytes.subarray(68, 96))));
  assert.equal(matchFreshWTLOSV3Event(context, emitter, hex(message), parsed), hex(inner));
  const roots = { historical: { index: 0n, root: 101n }, current: { index: 128n, root: 102n } };
  const hashRawMemo = raw => {
    assert.equal(raw, `0x${parsed.rawMemo}`);
    return memoDigests[txType];
  };
  const inputs = freshWTLOSV3VerifierInputs(context, source, hex(bytes), roots, hashRawMemo);
  assert.deepEqual(inputs.transfer, [101n, 1n, 2n, parsed.packedDeltaAndPoolId,
    BigInt(memoDigests[txType]) % field]);
  assert.deepEqual(inputs.tree, [102n, 3n, 2n]);
  assert.throws(() => freshWTLOSV3VerifierInputs(context, source, hex(bytes),
    { ...roots, historical: { index: 128n, root: 101n } }, hashRawMemo));
  assert.throws(() => freshWTLOSV3VerifierInputs(context, source, hex(bytes),
    { ...roots, current: { index: 1n, root: 102n } }, hashRawMemo));
  assert.throws(() => freshWTLOSV3VerifierInputs(context, source, hex(bytes),
    { ...roots, current: { index: 128n, root: field } }, hashRawMemo));
  assert.throws(() => freshWTLOSV3VerifierInputs(context, source, hex(bytes),
    { ...roots, current: { index: ((1n << 32n) - 1n) * 128n, root: 102n } }, hashRawMemo));
  const lastSuccessfulIndex = ((1n << 32n) - 2n) * 128n;
  assert.equal(freshWTLOSV3VerifierInputs(context, source, hex(bytes),
    { ...roots, current: { index: lastSuccessfulIndex, root: 102n } },
    hashRawMemo).tree[0], 102n);
  assert.throws(() => freshWTLOSV3VerifierInputs(context, source, hex(bytes), roots, () => '0x1234'));
  if (txType === '0000') {
    assert.equal(parsed.deadline, 1000n);
    assert.equal(parsed.compactSignature, '33'.repeat(64));
  } else {
    assert.equal(parsed.deadline, undefined);
    assert.equal(parsed.compactSignature, undefined);
  }
  if (txType === '0002') assert.equal(parsed.withdrawalRecipient, '0x' + '22'.repeat(20));
}

const deposit = makeCalldata('0000', 10n);
const reject = (bytes, ctx = context, src = source) =>
  assert.throws(() => parseFreshWTLOSV3Calldata(ctx, src, hex(bytes)));
const changed = (bytes, at, value) => { const copy = Buffer.from(bytes); copy[at] = value; return copy; };
reject(changed(deposit, 0, 0));
reject(deposit.subarray(0, deposit.length - 1));
reject(Buffer.concat([deposit, Buffer.from([0])]));
reject(changed(deposit, 643, deposit[643] + 1));
reject(changed(deposit, 640, 0x00).fill(3, 641, 642));
reject(changed(deposit, 656, 0)); // TPD1 tag in raw memo
reject(changed(deposit, 88, 0xff)); // deposit token delta becomes negative
reject(changed(deposit, 74, 1)); // energy must be zero
const noncanonical = Buffer.from(deposit);
be(21888242871839275222246405745257275088548364400416034343698204186575808495617n, 32)
  .copy(noncanonical, 4);
reject(noncanonical);
const zeroRoot = Buffer.from(deposit);
zeroRoot.fill(0, 352, 384);
reject(zeroRoot);
const zeroDeadline = Buffer.from(deposit);
zeroDeadline.fill(0, zeroDeadline.length - 72, zeroDeadline.length - 64);
reject(zeroDeadline);
reject(deposit, context, { ...source, to: '0x' + '44'.repeat(20) });
reject(deposit, context, { ...source, chainId: 41 });
reject(deposit, { ...context, poolId: 0 });
reject(makeCalldata('0001', 0n));
reject(makeCalldata('0002', -1n));
const transferWithTail = Buffer.concat([makeCalldata('0001', -fee), Buffer.alloc(72)]);
reject(transferWithTail);
const bridgeType = Buffer.from(makeCalldata('0001', -fee));
bridgeType[641] = 3;
reject(bridgeType);

const parsed = parseFreshWTLOSV3Calldata(context, source, hex(deposit));
const historicalDeposit = Buffer.from(deposit);
be(128, 6).copy(historicalDeposit, 68);
const historicalInputs = freshWTLOSV3VerifierInputs(context, source, hex(historicalDeposit),
  { historical: { index: 128n, root: 104n }, current: { index: 256n, root: 105n } },
  raw => { assert.equal(raw, `0x${parsed.rawMemo}`); return memoDigests['0000']; });
assert.equal(historicalInputs.transfer[0], 104n);
assert.equal(historicalInputs.tree[0], 105n);
assert.throws(() => freshWTLOSV3VerifierInputs(context, source, hex(historicalDeposit),
  { historical: { index: 128n, root: 104n }, current: { index: 0n, root: 105n } },
  () => memoDigests['0000']));
assert.throws(() => freshWTLOSV3VerifierInputs(context, source, hex(historicalDeposit),
  { historical: { index: 128n, root: 0n }, current: { index: 256n, root: 105n } },
  () => memoDigests['0000']));
assert.throws(() => matchFreshWTLOSV3Event(context, { ...emitter, emitter: '0x' + '44'.repeat(20) }, hex(message), parsed));
assert.throws(() => matchFreshWTLOSV3Event(context, emitter, hex(changed(message, 4, 0)), parsed));
assert.throws(() => matchFreshWTLOSV3Event({ ...context, poolId: 8 }, emitter, hex(message), parsed));

console.log('PASS_FRESH_WTLOS_V3_CALLDATA_SOURCE_ONLY');
