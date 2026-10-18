import assert from 'node:assert/strict';
import {
  unwrapFreshWTLOSV3EventMessage,
  unwrapFreshWTLOSV3RawMemo,
} from '../src/networks/evm/fresh-wtlos-v3-memo.ts';

const proxy = '0x' + '11'.repeat(20);
const context = { format: 'fresh-wtlos-v3', chainId: 40, poolId: 7, poolProxy: proxy };
const hex = bytes => Buffer.from(bytes).toString('hex');
const makeInner = count => {
  const bytes = Buffer.alloc(30 + 172 * count);
  bytes.writeUInt32LE(count, 0);
  bytes[4] = 0xaa;
  bytes[bytes.length - 1] = 0xbb;
  return bytes;
};
const makeMessage = inner => Buffer.concat([
  Buffer.alloc(4), Buffer.from('TPD1'), Buffer.from(proxy.slice(2), 'hex'),
  Buffer.from([inner.length >> 8, inner.length & 0xff]), inner,
]);
const fee = Buffer.from('0102030405060708', 'hex');

for (const count of [1, 2, 128]) {
  const inner = makeInner(count);
  const message = makeMessage(inner);
  const raw = Buffer.concat([fee, message]);
  assert.equal(unwrapFreshWTLOSV3EventMessage(context, hex(message)), hex(inner));
  assert.equal(unwrapFreshWTLOSV3EventMessage(context, `0x${hex(message)}`), hex(inner));
  assert.deepEqual(unwrapFreshWTLOSV3RawMemo(context, '0000', hex(raw)), {
    fee: 0x0102030405060708n, guardedMemo: hex(inner),
  });
  assert.equal(unwrapFreshWTLOSV3RawMemo(context, '0001', `0x${hex(raw)}`).guardedMemo, hex(inner));
  const recipient = Buffer.alloc(20, 0x22);
  const withdrawRaw = Buffer.concat([fee, Buffer.alloc(8), recipient, message]);
  assert.deepEqual(unwrapFreshWTLOSV3RawMemo(context, '0002', hex(withdrawRaw)), {
    fee: 0x0102030405060708n,
    guardedMemo: hex(inner),
    withdrawalRecipient: '0x' + '22'.repeat(20),
  });
}

const inner = makeInner(1);
const message = makeMessage(inner);
const rejectEvent = modified => assert.throws(() => unwrapFreshWTLOSV3EventMessage(context, hex(modified)));
const altered = (offset, value) => { const copy = Buffer.from(message); copy[offset] = value; return copy; };
rejectEvent(altered(0, 1));
rejectEvent(altered(4, 0));
rejectEvent(altered(8, 0));
rejectEvent(altered(29, 0));
rejectEvent(Buffer.concat([message, Buffer.from([0])]));
rejectEvent(message.subarray(0, message.length - 1));
rejectEvent(altered(30, 0));
const tooManyItems = Buffer.from(message);
tooManyItems.writeUInt32LE(129, 30);
rejectEvent(tooManyItems);
const wrongShape = Buffer.from(message);
wrongShape[29] += 1;
rejectEvent(wrongShape);
rejectEvent(Buffer.concat([fee, message]));
assert.throws(() => unwrapFreshWTLOSV3EventMessage(context, `0x${hex(message)}0`));
assert.throws(() => unwrapFreshWTLOSV3EventMessage(context, '0xzz'));
assert.throws(() => unwrapFreshWTLOSV3EventMessage({ ...context, poolProxy: '0x' + '33'.repeat(20) }, hex(message)));
assert.throws(() => unwrapFreshWTLOSV3EventMessage({ ...context, chainId: 41 }, hex(message)));
assert.throws(() => unwrapFreshWTLOSV3EventMessage({ ...context, poolId: 0 }, hex(message)));
assert.throws(() => unwrapFreshWTLOSV3EventMessage({ ...context, poolId: 1 << 24 }, hex(message)));
assert.throws(() => unwrapFreshWTLOSV3EventMessage({ ...context, poolId: Number.MAX_SAFE_INTEGER + 1 }, hex(message)));
assert.throws(() => unwrapFreshWTLOSV3EventMessage({ ...context, poolProxy: '0x' + '00'.repeat(20) }, hex(message)));
assert.throws(() => unwrapFreshWTLOSV3EventMessage({ ...context, format: 'legacy' }, hex(message)));

const raw = Buffer.concat([fee, message]);
assert.throws(() => unwrapFreshWTLOSV3RawMemo(context, '0003', hex(raw)));
assert.throws(() => unwrapFreshWTLOSV3RawMemo(context, '0000', hex(raw.subarray(0, 10))));
assert.throws(() => unwrapFreshWTLOSV3RawMemo(context, '0000', hex(message)));
const badNative = Buffer.concat([fee, Buffer.alloc(8), Buffer.alloc(20, 0x22), message]);
badNative[8] = 1;
assert.throws(() => unwrapFreshWTLOSV3RawMemo(context, '0002', hex(badNative)));
const zeroRecipient = Buffer.concat([fee, Buffer.alloc(8), Buffer.alloc(20), message]);
assert.throws(() => unwrapFreshWTLOSV3RawMemo(context, '0002', hex(zeroRecipient)));

console.log('PASS_FRESH_WTLOS_V3_MEMO_SOURCE_ONLY');
