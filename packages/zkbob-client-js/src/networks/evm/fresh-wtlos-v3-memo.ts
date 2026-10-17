/**
 * Source-only fresh WTLOS v3 memo adapter. The selected pool emits an outer
 * TPD1/proxy envelope, while its guarded cipher expects an inner Borsh memo.
 * Call only from a route selected by trusted pool configuration. The message
 * does not carry the pool ID, so the caller must bind pool ID to proxy and
 * transaction identity before calling. Never infer the pool version by
 * scanning an arbitrary legacy message for TPD1.
 */

export interface FreshWTLOSV3MemoContext {
  format: 'fresh-wtlos-v3';
  chainId: number;
  poolId: bigint | number | string;
  poolProxy: string;
}

export type FreshWTLOSV3TxType = '0000' | '0001' | '0002';

export interface FreshWTLOSV3RawMemo {
  fee: bigint;
  guardedMemo: string; // lowercase hex without 0x, for the future guarded parser
  withdrawalRecipient?: string;
}

const MAX_MEMO_BYTES = 65535;
const MAX_POOL_ID = (1n << 24n) - 1n;
const MAX_ITEMS = 128;
const DOMAIN_TAG = [0x54, 0x50, 0x44, 0x31]; // TPD1

function decodeHex(value: string, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be hex`);
  const raw = value.startsWith('0x') ? value.slice(2) : value;
  if (raw.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(raw)) {
    throw new Error(`${label} must be even-length hex`);
  }
  const bytes = new Uint8Array(raw.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function encodeHex(bytes: Uint8Array): string {
  return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

function allZero(bytes: Uint8Array): boolean {
  return bytes.every(value => value === 0);
}

function readU64BE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function readU32LE(bytes: Uint8Array): number {
  return bytes[0] + bytes[1] * 256 + bytes[2] * 65536 + bytes[3] * 16777216;
}

function trustedProxy(context: FreshWTLOSV3MemoContext): Uint8Array {
  if (context.format !== 'fresh-wtlos-v3' || context.chainId !== 40) {
    throw new Error('fresh WTLOS v3 memo requires trusted Telos EVM context');
  }
  if (typeof context.poolId === 'number' && !Number.isSafeInteger(context.poolId)) {
    throw new Error('fresh WTLOS pool ID is not a safe integer');
  }
  let poolId: bigint;
  try { poolId = BigInt(context.poolId); }
  catch { throw new Error('fresh WTLOS pool ID is invalid'); }
  if (poolId <= 0n || poolId > MAX_POOL_ID) throw new Error('fresh WTLOS pool ID is out of range');
  const proxy = decodeHex(context.poolProxy, 'poolProxy');
  if (proxy.length !== 20 || allZero(proxy)) throw new Error('fresh WTLOS pool proxy is invalid');
  return proxy;
}

function unwrapMessage(proxy: Uint8Array, message: Uint8Array): string {
  if (message.length < 30 || message.length > MAX_MEMO_BYTES) {
    throw new Error('fresh WTLOS event message length is invalid');
  }
  if (!allZero(message.subarray(0, 4))) throw new Error('fresh WTLOS outer marker is invalid');
  for (let i = 0; i < 4; i++) {
    if (message[4 + i] !== DOMAIN_TAG[i]) throw new Error('fresh WTLOS memo tag is invalid');
  }
  for (let i = 0; i < 20; i++) {
    if (message[8 + i] !== proxy[i]) throw new Error('fresh WTLOS memo proxy mismatch');
  }
  const innerLength = message[28] * 256 + message[29];
  if (innerLength < 4 || message.length !== 30 + innerLength) {
    throw new Error('fresh WTLOS guarded memo length mismatch');
  }
  const guarded = message.subarray(30);
  const count = readU32LE(guarded.subarray(0, 4));
  if (count < 1 || count > MAX_ITEMS) throw new Error('fresh WTLOS guarded item count is invalid');
  // Exact selected BN254 cipher::encrypt layout: 30 + 172 * count bytes.
  // This also rejects trailing bytes that the guarded decryptor would ignore.
  if (innerLength !== 30 + 172 * count) {
    throw new Error('fresh WTLOS guarded memo shape mismatch');
  }
  return encodeHex(guarded);
}

/** r12 Message event or subgraph tx.message, with or without 0x. */
export function unwrapFreshWTLOSV3EventMessage(
  context: FreshWTLOSV3MemoContext,
  eventMessage: string,
): string {
  return unwrapMessage(trustedProxy(context), decodeHex(eventMessage, 'eventMessage'));
}

/**
 * V1 transact calldata's decoded tx.memo, with or without 0x. The caller
 * must compare the returned fee and recipient to authenticated transaction
 * fields before using them as transaction facts.
 */
export function unwrapFreshWTLOSV3RawMemo(
  context: FreshWTLOSV3MemoContext,
  txType: FreshWTLOSV3TxType,
  rawMemo: string,
): FreshWTLOSV3RawMemo {
  const proxy = trustedProxy(context);
  if (txType !== '0000' && txType !== '0001' && txType !== '0002') {
    throw new Error('fresh WTLOS transaction type is unsupported');
  }
  const bytes = decodeHex(rawMemo, 'rawMemo');
  const fixedLength = txType === '0002' ? 36 : 8;
  if (bytes.length < fixedLength + 30 || bytes.length > MAX_MEMO_BYTES) {
    throw new Error('fresh WTLOS raw memo length is invalid');
  }
  const fee = readU64BE(bytes.subarray(0, 8));
  let withdrawalRecipient: string | undefined;
  if (txType === '0002') {
    if (!allZero(bytes.subarray(8, 16))) throw new Error('fresh WTLOS native withdrawal is forbidden');
    const recipient = bytes.subarray(16, 36);
    if (allZero(recipient)) throw new Error('fresh WTLOS withdrawal recipient cannot be zero');
    withdrawalRecipient = `0x${encodeHex(recipient)}`;
  }
  const guardedMemo = unwrapMessage(proxy, bytes.subarray(fixedLength));
  return { fee, guardedMemo, ...(withdrawalRecipient ? { withdrawalRecipient } : {}) };
}
