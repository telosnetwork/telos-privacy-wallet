import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const testDir = mkdtempSync(join(tmpdir(), 'fresh-wtlos-v3-receipt-'));
process.on('exit', () => rmSync(testDir, { recursive: true, force: true }));
writeFileSync(join(testDir, 'package.json'), '{"type":"module"}\n');
for (const name of ['fresh-wtlos-v3-memo', 'fresh-wtlos-v3-calldata', 'fresh-wtlos-v3-receipt']) {
  const source = readFileSync(new URL(`../src/networks/evm/${name}.ts`, import.meta.url), 'utf8');
  writeFileSync(join(testDir, `${name}.js`), stripTypeScriptTypes(source));
}
const { bindFreshWTLOSV3Receipt } =
  await import(pathToFileURL(join(testDir, 'fresh-wtlos-v3-receipt.js')).href);

const proxy = '0x' + '11'.repeat(20);
const context = { format: 'fresh-wtlos-v3', chainId: 40, poolId: 7, poolProxy: proxy };
const roots = { historical: { index: 0n, root: 101n }, current: { index: 128n, root: 102n } };
const topic0 = '0x7d39f8a6bc8929456fba511441be7361aa014ac6f8e21b99990ce9e1c7373536';
const messageDigest = '0x5a01680347609117be41c0f944bd6e0e48b8da37ff346bf87074f45c8c0a9308';
const rollingDigest = '0x5c2fba98375d4a182c830281e86b2b8bb7dc608aebe4bd0f8bd8cf2db50a8b1a';
const rawMemoDigest = '0x3aab3841e1fd09792994c9dfbcfd7362da89bb8fed44a888091b330b44a68888';
const prior = '0x' + '00'.repeat(32);
const hex = value => Buffer.from(value).toString('hex');
const be = (value, count) => {
  let n = BigInt(value);
  const data = Buffer.alloc(count);
  for (let i = count - 1; i >= 0; i--) { data[i] = Number(n & 255n); n >>= 8n; }
  assert.equal(n, 0n);
  return data;
};
const inner = Buffer.alloc(202);
inner.writeUInt32LE(1, 0);
inner[4] = 0xaa;
inner[201] = 0xbb;
const message = Buffer.concat([
  Buffer.alloc(4), Buffer.from('TPD1'), Buffer.from(proxy.slice(2), 'hex'), be(inner.length, 2), inner,
]);
const rawMemo = Buffer.concat([be(2, 8), message]);
const calldata = Buffer.concat([
  Buffer.from('af989083', 'hex'), be(1, 32), be(2, 32), be(0, 6),
  be(0, 14), be(10, 8), Buffer.alloc(256), be(3, 32), Buffer.alloc(256),
  Buffer.from('0000', 'hex'), be(rawMemo.length, 2), rawMemo,
  be(1000, 8), Buffer.alloc(64, 0x33),
]);
const data = Buffer.concat([
  be(32, 32), be(message.length, 32), message,
  Buffer.alloc((32 - message.length % 32) % 32),
]);
const hashInputs = new Map([
  [`0x${hex(rawMemo)}`, rawMemoDigest],
  [`0x${hex(message)}`, messageDigest],
  [`0x${'00'.repeat(32)}${messageDigest.slice(2)}`, rollingDigest],
]);
const keccak = value => {
  assert.ok(hashInputs.has(value), `unexpected Keccak input: ${value}`);
  return hashInputs.get(value);
};
const transaction = {
  hash: '0x' + '44'.repeat(32), to: proxy, input: `0x${hex(calldata)}`,
  blockHash: '0x' + '55'.repeat(32), blockNumber: 10n, transactionIndex: 3n,
};
const log = {
  address: proxy, topics: [topic0, `0x${hex(be(256, 32))}`, rollingDigest],
  data: `0x${hex(data)}`, transactionHash: transaction.hash,
  blockHash: transaction.blockHash, blockNumber: 10n, transactionIndex: 3n, logIndex: 8n,
};
const receipt = {
  transactionHash: transaction.hash, to: proxy, status: true,
  blockHash: transaction.blockHash, blockNumber: 10n, transactionIndex: 3n,
  logs: [log],
};
const bind = (tx = transaction, rcpt = receipt, snapshot = roots, oldHash = prior, chain = 40) =>
  bindFreshWTLOSV3Receipt(context, chain, tx, rcpt, snapshot, oldHash, keccak);
const result = bind();
assert.equal(result.eventIndex, 256n);
assert.equal(result.allMessagesHash, rollingDigest);
assert.equal(result.parsed.nextRoot, 3n);
assert.deepEqual(result.verifierInputs.tree, [102n, 3n, 2n]);
assert.equal(result.verifierInputs.transfer[0], 101n);
assert.equal(result.verifierInputs.transfer[4], BigInt(rawMemoDigest) %
  21888242871839275222246405745257275088548364400416034343698204186575808495617n);

const badReceipt = edit => { const copy = structuredClone(receipt); edit(copy); assert.throws(() => bind(transaction, copy)); };
const badTransaction = edit => { const copy = structuredClone(transaction); edit(copy); assert.throws(() => bind(copy)); };
badReceipt(copy => { copy.status = false; });
badReceipt(copy => { copy.transactionHash = '0x' + '66'.repeat(32); });
badReceipt(copy => { copy.transactionIndex = 4n; });
badReceipt(copy => { copy.blockHash = '0x' + '66'.repeat(32); });
badReceipt(copy => { copy.logs = []; });
badReceipt(copy => { copy.logs.push(structuredClone(copy.logs[0])); });
badReceipt(copy => { copy.logs[0].address = '0x' + '66'.repeat(20); });
badReceipt(copy => { copy.logs[0].transactionHash = '0x' + '66'.repeat(32); });
badReceipt(copy => { copy.logs[0].transactionIndex = 4n; });
badReceipt(copy => { copy.logs[0].topics[0] = '0x' + '66'.repeat(32); });
badReceipt(copy => { copy.logs[0].topics[1] = `0x${hex(be(128, 32))}`; });
badReceipt(copy => { copy.logs[0].topics[2] = '0x' + '66'.repeat(32); });
badReceipt(copy => { copy.logs[0].data = `0x${hex(data.subarray(0, data.length - 1))}`; });
badReceipt(copy => { const d = Buffer.from(data); d[31] = 0x40; copy.logs[0].data = `0x${hex(d)}`; });
badReceipt(copy => { const d = Buffer.from(data); d[d.length - 1] = 1; copy.logs[0].data = `0x${hex(d)}`; });
badTransaction(copy => { copy.to = '0x' + '66'.repeat(20); });
badTransaction(copy => { copy.hash = '0x' + '66'.repeat(32); });
assert.throws(() => bind(transaction, receipt, { ...roots, current: { index: 0n, root: 102n } }));
assert.throws(() => bind(transaction, receipt, roots, '0x' + '66'.repeat(32)));
assert.throws(() => bind(transaction, receipt, roots, prior, 41));

console.log('PASS_FRESH_WTLOS_V3_RECEIPT_SOURCE_ONLY');
