/**
 * Isolated r12 receipt-to-calldata binder. All records and the pre-state must
 * come from an authenticated, finality-aware chain source. This module only
 * checks their internal consistency; it does not authenticate RPC responses.
 */
import type { FreshWTLOSV3MemoContext } from './fresh-wtlos-v3-memo.js';
import {
  freshWTLOSV3VerifierInputs,
  matchFreshWTLOSV3Event,
  parseFreshWTLOSV3Calldata,
} from './fresh-wtlos-v3-calldata.js';
import type {
  FreshWTLOSV3ParsedCalldata,
  FreshWTLOSV3RootSnapshot,
  FreshWTLOSV3VerifierInputs,
} from './fresh-wtlos-v3-calldata.js';

const MESSAGE_TOPIC = '7d39f8a6bc8929456fba511441be7361aa014ac6f8e21b99990ce9e1c7373536';

export interface FreshWTLOSV3TransactionRecord {
  hash: string;
  to: string;
  input: string;
  blockHash: string;
  blockNumber: bigint;
  transactionIndex: bigint;
}

export interface FreshWTLOSV3LogRecord {
  address: string;
  topics: string[];
  data: string;
  transactionHash: string;
  blockHash: string;
  blockNumber: bigint;
  transactionIndex: bigint;
  logIndex: bigint;
}

export interface FreshWTLOSV3ReceiptRecord {
  transactionHash: string;
  to: string;
  status: boolean;
  blockHash: string;
  blockNumber: bigint;
  transactionIndex: bigint;
  logs: FreshWTLOSV3LogRecord[];
}

export interface FreshWTLOSV3BoundReceipt {
  parsed: FreshWTLOSV3ParsedCalldata;
  verifierInputs: FreshWTLOSV3VerifierInputs;
  eventIndex: bigint;
  allMessagesHash: string;
}

function bytes(value: string, label: string, expectedLength?: number): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be hex`);
  const raw = value.startsWith('0x') ? value.slice(2) : value;
  if (raw.length % 2 || !/^[0-9a-fA-F]*$/.test(raw)) throw new Error(`${label} must be even-length hex`);
  const result = new Uint8Array(raw.length / 2);
  if (expectedLength !== undefined && result.length !== expectedLength) {
    throw new Error(`${label} has incorrect length`);
  }
  for (let i = 0; i < result.length; i++) result[i] = Number.parseInt(raw.slice(2 * i, 2 * i + 2), 16);
  return result;
}

function hex(data: Uint8Array): string {
  return Array.from(data, byte => byte.toString(16).padStart(2, '0')).join('');
}

function uint(data: Uint8Array): bigint {
  let value = 0n;
  for (const byte of data) value = (value << 8n) | BigInt(byte);
  return value;
}

function requireAddress(value: string, label: string): string {
  const raw = bytes(value, label, 20);
  if (raw.every(byte => byte === 0)) throw new Error(`${label} cannot be zero`);
  return hex(raw);
}

function requireHash(value: string, label: string): string {
  return hex(bytes(value, label, 32));
}

function requirePosition(value: bigint, label: string): void {
  if (typeof value !== 'bigint' || value < 0n) throw new Error(`${label} must be a nonnegative bigint`);
}

function decodeMessageData(data: string): string {
  const raw = bytes(data, 'Message event data');
  if (raw.length < 64 || raw.length % 32 !== 0 || uint(raw.subarray(0, 32)) !== 32n) {
    throw new Error('Message event ABI offset or length is invalid');
  }
  const length = uint(raw.subarray(32, 64));
  const padded = ((length + 31n) / 32n) * 32n;
  if (64n + padded !== BigInt(raw.length)) throw new Error('Message event ABI byte length is invalid');
  const end = 64 + Number(length);
  if (raw.subarray(end).some(byte => byte !== 0)) throw new Error('Message event ABI padding is nonzero');
  return hex(raw.subarray(64, end));
}

/**
 * Bind one successful r12 transact to its sole pool Message log, rolling
 * message hash, and exact verifier inputs. `roots` and `priorMessagesHash`
 * must describe the pool immediately before this transaction, even when
 * earlier transactions occurred in the same block.
 */
export function bindFreshWTLOSV3Receipt(
  context: FreshWTLOSV3MemoContext,
  chainId: number,
  transaction: FreshWTLOSV3TransactionRecord,
  receipt: FreshWTLOSV3ReceiptRecord,
  roots: FreshWTLOSV3RootSnapshot,
  priorMessagesHash: string,
  keccak256Hex: (bytesHex: string) => string,
): FreshWTLOSV3BoundReceipt {
  const proxy = requireAddress(context.poolProxy, 'trusted pool proxy');
  if (requireAddress(transaction.to, 'transaction destination') !== proxy ||
      requireAddress(receipt.to, 'receipt destination') !== proxy) {
    throw new Error('fresh WTLOS transaction destination is not the trusted pool');
  }
  const txHash = requireHash(transaction.hash, 'transaction hash');
  const blockHash = requireHash(transaction.blockHash, 'transaction block hash');
  requirePosition(transaction.blockNumber, 'transaction block number');
  requirePosition(transaction.transactionIndex, 'transaction index');
  if (receipt.status !== true || requireHash(receipt.transactionHash, 'receipt transaction hash') !== txHash ||
      requireHash(receipt.blockHash, 'receipt block hash') !== blockHash ||
      receipt.blockNumber !== transaction.blockNumber ||
      receipt.transactionIndex !== transaction.transactionIndex) {
    throw new Error('fresh WTLOS receipt does not match a successful transaction');
  }

  const parsed = parseFreshWTLOSV3Calldata(context,
    { chainId, to: transaction.to }, transaction.input);
  const verifierInputs = freshWTLOSV3VerifierInputs(context,
    { chainId, to: transaction.to }, transaction.input, roots, keccak256Hex);
  const messageLogs = receipt.logs.filter(log =>
    requireAddress(log.address, 'log emitter') === proxy &&
    log.topics.length > 0 && requireHash(log.topics[0], 'log topic0') === MESSAGE_TOPIC);
  if (messageLogs.length !== 1) throw new Error('expected exactly one fresh WTLOS Message log');
  const log = messageLogs[0];
  requirePosition(log.logIndex, 'log index');
  if (requireHash(log.transactionHash, 'log transaction hash') !== txHash ||
      requireHash(log.blockHash, 'log block hash') !== blockHash ||
      log.blockNumber !== transaction.blockNumber ||
      log.transactionIndex !== transaction.transactionIndex ||
      log.topics.length !== 3) {
    throw new Error('fresh WTLOS Message log provenance is inconsistent');
  }
  const eventIndex = uint(bytes(log.topics[1], 'Message index topic', 32));
  if (eventIndex !== roots.current.index + 128n) {
    throw new Error('fresh WTLOS Message index does not follow the current root');
  }
  const allMessagesHash = requireHash(log.topics[2], 'Message hash topic');
  const eventMessage = decodeMessageData(log.data);
  matchFreshWTLOSV3Event(context, { chainId, emitter: log.address }, eventMessage, parsed);

  const previous = requireHash(priorMessagesHash, 'prior all-messages hash');
  const messageHash = requireHash(keccak256Hex(`0x${eventMessage}`), 'Message Keccak-256');
  const expected = requireHash(keccak256Hex(`0x${previous}${messageHash}`), 'rolling Keccak-256');
  if (allMessagesHash !== expected) throw new Error('fresh WTLOS rolling message hash mismatch');
  return { parsed, verifierInputs, eventIndex, allMessagesHash: `0x${allMessagesHash}` };
}
