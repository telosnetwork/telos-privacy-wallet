import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const testDir = mkdtempSync(join(tmpdir(), 'fresh-wtlos-v3-history-'));
process.on('exit', () => rmSync(testDir, { recursive: true, force: true }));
writeFileSync(join(testDir, 'package.json'), '{"type":"module"}\n');
for (const name of ['fresh-wtlos-v3-memo', 'fresh-wtlos-v3-calldata',
  'fresh-wtlos-v3-receipt', 'fresh-wtlos-v3-history']) {
  const source = readFileSync(new URL(`../src/networks/evm/${name}.ts`, import.meta.url), 'utf8');
  writeFileSync(join(testDir, `${name}.js`), stripTypeScriptTypes(source));
}
const { FreshWTLOSV3HistoryReplay } =
  await import(pathToFileURL(join(testDir, 'fresh-wtlos-v3-history.js')).href);

const proxy = '0x' + '11'.repeat(20);
const context = { format: 'fresh-wtlos-v3', chainId: 40, poolId: 7, poolProxy: proxy };
const initialRoot = 11469701942666298368112882412133877458305516134926649826543144744382391691533n;
const zero = '0x' + '00'.repeat(32);
const topic0 = '0x7d39f8a6bc8929456fba511441be7361aa014ac6f8e21b99990ce9e1c7373536';
const rawDigest = '0x3aab3841e1fd09792994c9dfbcfd7362da89bb8fed44a888091b330b44a68888';
const messageDigest = '0x5a01680347609117be41c0f944bd6e0e48b8da37ff346bf87074f45c8c0a9308';
const firstHash = '0x5c2fba98375d4a182c830281e86b2b8bb7dc608aebe4bd0f8bd8cf2db50a8b1a';
const secondHash = '0xac0b134f58d5449d548db1c25d3792cca02492095c1b4a7ddd7f8b3878961fdd';
const hex = value => Buffer.from(value).toString('hex');
const be = (value, count) => {
  let n = BigInt(value);
  if (n < 0n) n += 1n << BigInt(count * 8);
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
  Buffer.alloc(4), Buffer.from('TPD1'), Buffer.from(proxy.slice(2), 'hex'), be(202, 2), inner,
]);
const rawMemo = Buffer.concat([be(2, 8), message]);
const abiData = Buffer.concat([
  be(32, 32), be(message.length, 32), message,
  Buffer.alloc((32 - message.length % 32) % 32),
]);
const hashInputs = new Map([
  [`0x${hex(rawMemo)}`, rawDigest],
  [`0x${hex(message)}`, messageDigest],
  [`0x${'00'.repeat(32)}${messageDigest.slice(2)}`, firstHash],
  [`0x${firstHash.slice(2)}${messageDigest.slice(2)}`, secondHash],
]);
const keccak = value => {
  assert.ok(hashInputs.has(value), `unexpected Keccak input: ${value}`);
  return hashInputs.get(value);
};

function operation({ txType, delta, nullifier, outCommit, historicalIndex, nextRoot,
  eventIndex, allHash, txIndex }) {
  const tail = txType === '0000' ? Buffer.concat([be(1000, 8), Buffer.alloc(64, 0x33)]) : Buffer.alloc(0);
  const input = Buffer.concat([
    Buffer.from('af989083', 'hex'), be(nullifier, 32), be(outCommit, 32),
    be(historicalIndex, 6), be(0, 14), be(delta, 8),
    Buffer.alloc(256), be(nextRoot, 32), Buffer.alloc(256),
    Buffer.from(txType, 'hex'), be(rawMemo.length, 2), rawMemo, tail,
  ]);
  const transaction = {
    hash: '0x' + txIndex.toString(16).padStart(2, '0').repeat(32), to: proxy,
    input: `0x${hex(input)}`, blockHash: '0x' + '55'.repeat(32),
    blockNumber: 10n, transactionIndex: BigInt(txIndex),
  };
  const log = {
    address: proxy, topics: [topic0, `0x${hex(be(eventIndex, 32))}`, allHash],
    data: `0x${hex(abiData)}`, transactionHash: transaction.hash,
    blockHash: transaction.blockHash, blockNumber: 10n,
    transactionIndex: BigInt(txIndex), logIndex: BigInt(txIndex + 5),
  };
  const receipt = {
    transactionHash: transaction.hash, to: proxy, status: true,
    blockHash: transaction.blockHash, blockNumber: 10n,
    transactionIndex: BigInt(txIndex), logs: [log],
  };
  return { transaction, receipt };
}

const first = operation({ txType: '0000', delta: 10n, nullifier: 1n, outCommit: 2n,
  historicalIndex: 0n, nextRoot: 3n, eventIndex: 128n, allHash: firstHash, txIndex: 3 });
const second = operation({ txType: '0001', delta: -2n, nullifier: 4n, outCommit: 5n,
  historicalIndex: 0n, nextRoot: 6n, eventIndex: 256n, allHash: secondHash, txIndex: 4 });

const replay = new FreshWTLOSV3HistoryReplay(context);
assert.deepEqual(replay.checkpoint(),
  { currentIndex: 0n, currentRoot: initialRoot, allMessagesHash: zero });
const firstResult = replay.advance(40, first.transaction, first.receipt, keccak);
assert.equal(firstResult.verifierInputs.transfer[0], initialRoot);
assert.equal(firstResult.verifierInputs.tree[0], initialRoot);
assert.deepEqual(replay.checkpoint(),
  { currentIndex: 128n, currentRoot: 3n, allMessagesHash: firstHash });

const forkedSecond = structuredClone(second);
forkedSecond.transaction.blockHash = '0x' + '66'.repeat(32);
forkedSecond.receipt.blockHash = forkedSecond.transaction.blockHash;
forkedSecond.receipt.logs[0].blockHash = forkedSecond.transaction.blockHash;
assert.throws(() => replay.advance(40, forkedSecond.transaction, forkedSecond.receipt, keccak));
assert.equal(replay.checkpoint().currentIndex, 128n);

const badSecond = structuredClone(second);
badSecond.receipt.logs[0].topics[2] = zero;
assert.throws(() => replay.advance(40, badSecond.transaction, badSecond.receipt, keccak));
assert.deepEqual(replay.checkpoint(),
  { currentIndex: 128n, currentRoot: 3n, allMessagesHash: firstHash });

const secondResult = replay.advance(40, second.transaction, second.receipt, keccak);
assert.equal(secondResult.verifierInputs.transfer[0], initialRoot);
assert.equal(secondResult.verifierInputs.tree[0], 3n);
assert.deepEqual(replay.checkpoint(),
  { currentIndex: 256n, currentRoot: 6n, allMessagesHash: secondHash });
replay.assertCheckpoint({ currentIndex: 256n, currentRoot: 6n, allMessagesHash: secondHash });
assert.throws(() => replay.assertCheckpoint({ currentIndex: 256n, currentRoot: 7n, allMessagesHash: secondHash }));
assert.throws(() => replay.advance(40, second.transaction, second.receipt, keccak));

const missingFirst = new FreshWTLOSV3HistoryReplay(context);
assert.throws(() => missingFirst.advance(40, second.transaction, second.receipt, keccak));
const reentrant = new FreshWTLOSV3HistoryReplay(context);
const reentrantHash = value => {
  reentrant.advance(40, first.transaction, first.receipt, keccak);
  return keccak(value);
};
assert.throws(() => reentrant.advance(40, first.transaction, first.receipt, reentrantHash));
assert.deepEqual(reentrant.checkpoint(),
  { currentIndex: 0n, currentRoot: initialRoot, allMessagesHash: zero });
reentrant.advance(40, first.transaction, first.receipt, keccak);

const mutationReplay = new FreshWTLOSV3HistoryReplay(context);
const mutableFirst = structuredClone(first);
const mutatingHash = value => {
  mutableFirst.transaction.blockNumber = 99n;
  mutableFirst.transaction.input = '0x';
  mutableFirst.receipt.status = false;
  return keccak(value);
};
mutationReplay.advance(40, mutableFirst.transaction, mutableFirst.receipt, mutatingHash);
mutationReplay.advance(40, second.transaction, second.receipt, keccak);
assert.equal(mutationReplay.checkpoint().currentIndex, 256n);

const wrongBlockOrder = structuredClone(second);
wrongBlockOrder.transaction.blockNumber = 9n;
wrongBlockOrder.receipt.blockNumber = 9n;
wrongBlockOrder.receipt.logs[0].blockNumber = 9n;
assert.throws(() => replay.advance(40, wrongBlockOrder.transaction, wrongBlockOrder.receipt, keccak));
const badContext = { ...context, poolId: 0 };
assert.throws(() => new FreshWTLOSV3HistoryReplay(badContext));

console.log('PASS_FRESH_WTLOS_V3_HISTORY_SOURCE_ONLY');
