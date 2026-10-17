import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  buildFreshWTLOSV3Intent,
  buildFreshWTLOSV3IntentFromTransaction,
  freshWTLOSV3MemoAndSignature,
  signFreshWTLOSV3Transaction,
} from '../src/signers/fresh-wtlos-v3-intent.ts';

const vector = JSON.parse(readFileSync(new URL('./fixtures/fresh-wtlos-v3-vector.json', import.meta.url)));
const source = vector.sourceValues;
const expectedMemo = source.memoDataHex.toLowerCase();
let hashedMemo = '';
const intent = buildFreshWTLOSV3Intent({
  chainId: vector.domain.chainId,
  poolProxy: vector.domain.verifyingContract,
  root: source.root,
  nullifier: source.nullifier,
  outCommit: source.outCommit,
  packedDeltaAndPoolId: vector.expected.packedDeltaAndPoolId,
  rawMemo: source.memoDataHex,
  deadline: source.deadline,
  operator: source.operator,
}, rawHex => {
  hashedMemo = rawHex;
  return vector.expected.memoDataHash;
});

assert.equal(hashedMemo, expectedMemo);
assert.equal(intent.rawMemo, expectedMemo);
assert.deepEqual(intent.typedData.types, vector.types);
assert.deepEqual(intent.typedData.domain, {
  ...vector.domain,
  chainId: String(vector.domain.chainId),
});
assert.deepEqual(intent.typedData.message, vector.message);

const fieldModulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const tx = {
  public: {
    root: source.root,
    nullifier: source.nullifier,
    out_commit: source.outCommit,
    delta: vector.expected.packedDeltaAndPoolId,
    memo: (BigInt(vector.expected.memoDataHash) % fieldModulus).toString(),
  },
  memo: source.memoDataHex,
};
const fromTx = buildFreshWTLOSV3IntentFromTransaction(
  tx, vector.domain.chainId, vector.domain.verifyingContract, source.poolId,
  source.deadline, source.operator, () => vector.expected.memoDataHash,
);
assert.deepEqual(fromTx.typedData, intent.typedData);
assert.throws(() => buildFreshWTLOSV3IntentFromTransaction(
  { ...tx, public: { ...tx.public, memo: '1' } },
  vector.domain.chainId, vector.domain.verifyingContract, source.poolId,
  source.deadline, source.operator, () => vector.expected.memoDataHash,
));
assert.throws(() => buildFreshWTLOSV3IntentFromTransaction(
  tx, vector.domain.chainId, vector.domain.verifyingContract, '40004',
  source.deadline, source.operator, () => vector.expected.memoDataHash,
));

const signature = `0x${'0'.repeat(63)}1${'0'.repeat(63)}1`;
const encoded = freshWTLOSV3MemoAndSignature(expectedMemo, source.deadline, signature);
assert.equal(encoded, `${expectedMemo}${BigInt(source.deadline).toString(16).padStart(16, '0')}${signature.slice(2)}`);
assert.equal((encoded.length - 2) / 2, (expectedMemo.length - 2) / 2 + 8 + 64);

const fields = {
  chainId: vector.domain.chainId,
  poolProxy: vector.domain.verifyingContract,
  root: source.root,
  nullifier: source.nullifier,
  outCommit: source.outCommit,
  packedDeltaAndPoolId: vector.expected.packedDeltaAndPoolId,
  rawMemo: source.memoDataHex,
  deadline: source.deadline,
  operator: source.operator,
};
const hash = () => vector.expected.memoDataHash;
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, root: '21888242871839275222246405745257275088548364400416034343698204186575808495617' }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, deadline: (1n << 64n) }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, deadline: 0 }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, poolProxy: '0x' + '0'.repeat(40) }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, rawMemo: '0x123' }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, rawMemo: '0x' + '00'.repeat(12) }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, rawMemo: fields.rawMemo.replace('54504431', '54504432') }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, rawMemo: fields.rawMemo.replace('1111111111111111111111111111111111111111', '3333333333333333333333333333333333333333') }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, packedDeltaAndPoolId: ((BigInt(source.poolId) << 224n) + (1n << 64n) - BigInt(source.fee)).toString() }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, packedDeltaAndPoolId: ((BigInt(source.poolId) << 224n) + (1n << 64n) + BigInt(source.tokenDelta)).toString() }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, operator: '0x' + '0'.repeat(40) }, hash));
assert.throws(() => buildFreshWTLOSV3Intent({ ...fields, chainId: Number.MAX_SAFE_INTEGER + 1 }, hash));
assert.throws(() => freshWTLOSV3MemoAndSignature(expectedMemo, source.deadline, '0x' + '0'.repeat(128)));
assert.throws(() => freshWTLOSV3MemoAndSignature('0x' + '00'.repeat(12), source.deadline, signature));
assert.throws(() => freshWTLOSV3MemoAndSignature(expectedMemo, 0, signature));
assert.throws(() => freshWTLOSV3MemoAndSignature(expectedMemo, source.deadline, '0x' + '1'.repeat(130)));
const highS = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n / 2n + 1n;
assert.throws(() => freshWTLOSV3MemoAndSignature(
  expectedMemo, source.deadline,
  `0x${'0'.repeat(63)}1${highS.toString(16).padStart(64, '0')}`,
));

const depositor = '0x3333333333333333333333333333333333333333';
let recoveredStatement;
const mockBackend = {
  getChainId: async () => 40,
  toCompactSignature: value => value,
  recoverSignerTypedData: async (typedData, compact) => {
    recoveredStatement = typedData;
    assert.equal(compact, signature);
    return depositor;
  },
};
const sign = (request) => {
  assert.equal(request.type, 1);
  assert.deepEqual(request.data, intent.typedData);
  return Promise.resolve(signature);
};
const signed = await signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash, mockBackend, sign,
  () => Number(source.deadline) - 10,
);
assert.equal(signed.memoAndSignature, encoded);
assert.equal(signed.rawMemo, expectedMemo);
assert.equal(signed.compactSignature, signature);
assert.deepEqual(recoveredStatement, intent.typedData);
let retainedRequest;
const aliasSafe = await signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash, mockBackend,
  async request => { retainedRequest = request.data; return signature; },
  () => Number(source.deadline) - 10,
);
retainedRequest.message.operator = '0x4444444444444444444444444444444444444444';
assert.equal(aliasSafe.typedData.message.operator, source.operator.toLowerCase());
assert.throws(() => { aliasSafe.typedData.message.operator = source.operator; }, TypeError);
await assert.rejects(signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash,
  { ...mockBackend, getChainId: async () => 41 }, sign, () => Number(source.deadline) - 10,
), /chain 40/);
await assert.rejects(signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash, mockBackend,
  async request => { request.data.domain.chainId = '41'; return signature; },
  () => Number(source.deadline) - 10,
), /changed during signing/);
await assert.rejects(signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash,
  { ...mockBackend, recoverSignerTypedData: async () => source.operator }, sign,
  () => Number(source.deadline) - 10,
), /does not match depositor/);
await assert.rejects(signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash,
  mockBackend, sign, () => Number(source.deadline),
), /deadline has passed/);
await assert.rejects(signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash,
  mockBackend, sign, (() => { let calls = 0; return () => Number(source.deadline) - (calls++ ? 0 : 10); })(),
), /expired during signing/);
await assert.rejects(signFreshWTLOSV3Transaction(
  tx, vector.domain.verifyingContract, source.poolId, depositor, source.deadline,
  source.operator, () => vector.expected.memoDataHash,
  { ...mockBackend, toCompactSignature: () => `0x${'0'.repeat(63)}1${highS.toString(16).padStart(64, '0')}` },
  sign, () => Number(source.deadline) - 10,
), /not canonical/);

console.log('PASS_FRESH_WTLOS_V3_INTENT_SOURCE_ONLY');
