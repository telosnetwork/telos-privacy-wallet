/**
 * Isolated source-only decoder for the r12 fresh WTLOS transact() byte layout.
 * Observed chain, destination and log emitter must come from authenticated
 * RPC/receipt data; caller-provided strings do not establish provenance.
 */
import type { FreshWTLOSV3MemoContext, FreshWTLOSV3TxType } from './fresh-wtlos-v3-memo.js';
import {
  unwrapFreshWTLOSV3EventMessage,
  unwrapFreshWTLOSV3RawMemo,
} from './fresh-wtlos-v3-memo.js';

const SELECTOR = 'af989083'; // keccak256("transact()")[0..4]
const FIXED_BYTES = 644;
const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DELTA_SCALE = 1n << 224n;
// _recordOperation increments a uint32 count before a successful transact.
const MAX_SUCCESSFUL_PRE_TRANSACTION_INDEX = ((1n << 32n) - 2n) * 128n;

export interface FreshWTLOSV3CalldataSource {
  chainId: number;
  to: string;
}

export interface FreshWTLOSV3EventSource {
  chainId: number;
  emitter: string;
}

export interface FreshWTLOSV3ParsedCalldata {
  chainId: 40;
  poolId: bigint;
  poolProxy: string;
  txType: FreshWTLOSV3TxType;
  nullifier: bigint;
  outCommit: bigint;
  transferIndex: bigint;
  energyAmount: bigint;
  transferTokenDelta: bigint; // signed circuit delta, in 1e-9 WTLOS units
  poolTokenFlowUnits: bigint; // signed requested pool flow: delta + fee
  packedDeltaAndPoolId: bigint;
  nextRoot: bigint;
  fee: bigint;
  rawMemo: string; // lowercase hex without 0x
  eventMessage: string; // lowercase hex without 0x
  guardedMemo: string; // lowercase hex without 0x
  withdrawalRecipient?: string;
  deadline?: bigint;
  compactSignature?: string; // lowercase hex without 0x; not authenticated here
}

/** Both values must be read from the authenticated pre-transaction pool state. */
export interface FreshWTLOSV3RootSnapshot {
  historical: { index: bigint; root: bigint };
  current: { index: bigint; root: bigint };
}

export interface FreshWTLOSV3VerifierInputs {
  transfer: [bigint, bigint, bigint, bigint, bigint];
  tree: [bigint, bigint, bigint];
}

/** Opaque proof bytes must come from a separately qualified guarded prover. */
export interface FreshWTLOSV3CalldataAssembly {
  txType: FreshWTLOSV3TxType;
  nullifier: bigint;
  outCommit: bigint;
  transferIndex: bigint;
  energyAmount: bigint;
  transferTokenDelta: bigint;
  transferProof: string; // eight 32-byte words, not verified here
  nextRoot: bigint;
  treeProof: string; // eight 32-byte words, not verified here
  rawMemo: string; // exact final memo signed by the guarded owner
  deadline?: bigint; // type-0 deposit only
  compactSignature?: string; // type-0 EIP-2098 r||vs, not verified here
}

function hexBytes(value: string, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be hex`);
  const raw = value.startsWith('0x') ? value.slice(2) : value;
  if (raw.length % 2 || !/^[0-9a-fA-F]*$/.test(raw)) throw new Error(`${label} must be even-length hex`);
  const bytes = new Uint8Array(raw.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(raw.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function address(value: string, label: string): string {
  const bytes = hexBytes(value, label);
  if (bytes.length !== 20 || bytes.every(byte => byte === 0)) throw new Error(`${label} is invalid`);
  return hex(bytes);
}

function unsigned(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function encodeUnsigned(value: bigint, size: number, label: string): Uint8Array {
  if (typeof value !== 'bigint' || value < 0n || value >= (1n << BigInt(size * 8))) {
    throw new Error(`${label} is out of range`);
  }
  const result = new Uint8Array(size);
  let rest = value;
  for (let i = size - 1; i >= 0; i--) {
    result[i] = Number(rest & 255n);
    rest >>= 8n;
  }
  return result;
}

function encodeSigned(value: bigint, size: number, label: string): Uint8Array {
  const bits = BigInt(size * 8);
  if (typeof value !== 'bigint' || value < -(1n << (bits - 1n)) ||
      value >= (1n << (bits - 1n))) {
    throw new Error(`${label} is out of range`);
  }
  return encodeUnsigned(value < 0n ? (1n << bits) + value : value, size, label);
}

/**
 * Assemble the selected r12 custom calldata layout from final public fields,
 * two opaque proof byte arrays and the already-finalized raw memo. Parsing the
 * result checks the route, memo domain, economics and deposit tail. This does
 * not create or verify a witness, either proof, or the depositor signature.
 */
export function assembleFreshWTLOSV3Calldata(
  context: FreshWTLOSV3MemoContext,
  source: FreshWTLOSV3CalldataSource,
  fields: FreshWTLOSV3CalldataAssembly,
): string {
  if (fields.txType !== '0000' && fields.txType !== '0001' && fields.txType !== '0002') {
    throw new Error('fresh WTLOS transaction type is unsupported');
  }
  if (typeof fields.nullifier !== 'bigint' || fields.nullifier < 0n ||
      fields.nullifier >= FIELD_MODULUS || typeof fields.outCommit !== 'bigint' ||
      fields.outCommit < 0n || fields.outCommit >= FIELD_MODULUS ||
      typeof fields.nextRoot !== 'bigint' || fields.nextRoot <= 0n ||
      fields.nextRoot >= FIELD_MODULUS) {
    throw new Error('fresh WTLOS public field is not canonical');
  }
  if (typeof fields.transferIndex !== 'bigint' || fields.transferIndex < 0n ||
      fields.transferIndex > MAX_SUCCESSFUL_PRE_TRANSACTION_INDEX ||
      fields.transferIndex % 128n !== 0n) {
    throw new Error('fresh WTLOS transfer index is not a reachable root index');
  }
  const transferProof = hexBytes(fields.transferProof, 'transfer proof');
  const treeProof = hexBytes(fields.treeProof, 'tree proof');
  if (transferProof.length !== 256 || treeProof.length !== 256) {
    throw new Error('fresh WTLOS proofs must each have eight 32-byte words');
  }
  const rawMemo = hexBytes(fields.rawMemo, 'raw memo');
  if (rawMemo.length > 65535) throw new Error('fresh WTLOS memo is too long');
  let tail = new Uint8Array(0);
  if (fields.txType === '0000') {
    if (fields.deadline === undefined || fields.deadline === 0n ||
        fields.compactSignature === undefined) {
      throw new Error('fresh WTLOS deposit requires deadline and compact signature');
    }
    const signature = hexBytes(fields.compactSignature, 'compact signature');
    if (signature.length !== 64) throw new Error('fresh WTLOS compact signature must be 64 bytes');
    tail = new Uint8Array(72);
    tail.set(encodeUnsigned(fields.deadline, 8, 'deposit deadline'), 0);
    tail.set(signature, 8);
  } else if (fields.deadline !== undefined || fields.compactSignature !== undefined) {
    throw new Error('fresh WTLOS non-deposit transaction cannot have a signature tail');
  }
  const parts = [hexBytes(SELECTOR, 'selector'),
    encodeUnsigned(fields.nullifier, 32, 'nullifier'),
    encodeUnsigned(fields.outCommit, 32, 'output commitment'),
    encodeUnsigned(fields.transferIndex, 6, 'transfer index'),
    encodeSigned(fields.energyAmount, 14, 'energy amount'),
    encodeSigned(fields.transferTokenDelta, 8, 'transfer token delta'),
    transferProof,
    encodeUnsigned(fields.nextRoot, 32, 'next root'),
    treeProof,
    hexBytes(fields.txType, 'transaction type'),
    encodeUnsigned(BigInt(rawMemo.length), 2, 'memo length'), rawMemo, tail];
  const bytes = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  const calldata = `0x${hex(bytes)}`;
  parseFreshWTLOSV3Calldata(context, source, calldata);
  return calldata;
}

function signed(bytes: Uint8Array): bigint {
  const value = unsigned(bytes);
  const bits = BigInt(bytes.length * 8);
  return (value & (1n << (bits - 1n))) === 0n ? value : value - (1n << bits);
}

function trustedPoolId(context: FreshWTLOSV3MemoContext): bigint {
  if (typeof context.poolId === 'number' && !Number.isSafeInteger(context.poolId)) {
    throw new Error('pool ID is not a safe integer');
  }
  let poolId: bigint;
  try { poolId = BigInt(context.poolId); }
  catch { throw new Error('pool ID is invalid'); }
  if (poolId <= 0n || poolId >= (1n << 24n)) throw new Error('pool ID is out of range');
  return poolId;
}

function requireSource(context: FreshWTLOSV3MemoContext, chainId: number, observedAddress: string): bigint {
  if (context.format !== 'fresh-wtlos-v3' || context.chainId !== 40 || chainId !== 40) {
    throw new Error('fresh WTLOS source requires trusted chain-40 route');
  }
  if (address(observedAddress, 'observed address') !== address(context.poolProxy, 'pool proxy')) {
    throw new Error('fresh WTLOS source address does not match pool proxy');
  }
  return trustedPoolId(context);
}

function canonical(bytes: Uint8Array, label: string): bigint {
  const value = unsigned(bytes);
  if (value >= FIELD_MODULUS) throw new Error(`${label} is not a canonical field element`);
  return value;
}

/**
 * Decode an authenticated chain-40 transaction addressed to the trusted fresh
 * proxy. The resulting proof and compact signature are not verified here.
 */
export function parseFreshWTLOSV3Calldata(
  context: FreshWTLOSV3MemoContext,
  source: FreshWTLOSV3CalldataSource,
  calldata: string,
): FreshWTLOSV3ParsedCalldata {
  const poolId = requireSource(context, source.chainId, source.to);
  const bytes = hexBytes(calldata, 'calldata');
  if (bytes.length < FIXED_BYTES || hex(bytes.subarray(0, 4)) !== SELECTOR) {
    throw new Error('fresh WTLOS transact selector or fixed length is invalid');
  }
  const nullifier = canonical(bytes.subarray(4, 36), 'nullifier');
  const outCommit = canonical(bytes.subarray(36, 68), 'output commitment');
  const transferIndex = unsigned(bytes.subarray(68, 74));
  const energyAmount = signed(bytes.subarray(74, 88));
  const transferTokenDelta = signed(bytes.subarray(88, 96));
  const packedDeltaAndPoolId = poolId * DELTA_SCALE + unsigned(bytes.subarray(68, 96));
  const nextRoot = canonical(bytes.subarray(352, 384), 'next root');
  if (nextRoot === 0n) throw new Error('fresh WTLOS next root cannot be zero');
  const txType = hex(bytes.subarray(640, 642));
  if (txType !== '0000' && txType !== '0001' && txType !== '0002') {
    throw new Error('fresh WTLOS transaction type is unsupported');
  }
  const memoLength = Number(unsigned(bytes.subarray(642, 644)));
  const tailLength = txType === '0000' ? 72 : 0;
  if (bytes.length !== FIXED_BYTES + memoLength + tailLength) {
    throw new Error('fresh WTLOS calldata length does not match memo and tail');
  }
  const rawMemo = hex(bytes.subarray(FIXED_BYTES, FIXED_BYTES + memoLength));
  const memo = unwrapFreshWTLOSV3RawMemo(context, txType, rawMemo);
  const poolTokenFlowUnits = transferTokenDelta + memo.fee;
  if (energyAmount !== 0n ||
      (txType === '0000' && transferTokenDelta <= 0n) ||
      (txType === '0001' && poolTokenFlowUnits !== 0n) ||
      (txType === '0002' && poolTokenFlowUnits >= 0n)) {
    throw new Error('fresh WTLOS transaction economics are invalid');
  }
  const messageOffset = FIXED_BYTES + (txType === '0002' ? 36 : 8);
  const eventMessage = hex(bytes.subarray(messageOffset, FIXED_BYTES + memoLength));
  const result: FreshWTLOSV3ParsedCalldata = {
    chainId: 40, poolId, poolProxy: `0x${address(context.poolProxy, 'pool proxy')}`,
    txType, nullifier, outCommit, transferIndex, energyAmount,
    transferTokenDelta, poolTokenFlowUnits, packedDeltaAndPoolId,
    nextRoot, fee: memo.fee, rawMemo, eventMessage,
    guardedMemo: memo.guardedMemo,
  };
  if (memo.withdrawalRecipient) result.withdrawalRecipient = memo.withdrawalRecipient;
  if (txType === '0000') {
    const deadline = unsigned(bytes.subarray(FIXED_BYTES + memoLength, FIXED_BYTES + memoLength + 8));
    if (deadline === 0n) throw new Error('fresh WTLOS deposit deadline cannot be zero');
    result.deadline = deadline;
    result.compactSignature = hex(bytes.subarray(FIXED_BYTES + memoLength + 8));
  }
  return result;
}

/**
 * Cross-check a receipt Message against the parsed calldata. The caller must
 * separately authenticate receipt status, transaction hash and log index.
 */
export function matchFreshWTLOSV3Event(
  context: FreshWTLOSV3MemoContext,
  source: FreshWTLOSV3EventSource,
  eventMessage: string,
  parsed: FreshWTLOSV3ParsedCalldata,
): string {
  const poolId = requireSource(context, source.chainId, source.emitter);
  if (parsed.chainId !== 40 || parsed.poolId !== poolId ||
      parsed.poolProxy !== `0x${address(context.poolProxy, 'pool proxy')}`) {
    throw new Error('fresh WTLOS parsed transaction route mismatch');
  }
  const actual = hex(hexBytes(eventMessage, 'eventMessage'));
  if (actual !== parsed.eventMessage) throw new Error('fresh WTLOS event and calldata message mismatch');
  const guarded = unwrapFreshWTLOSV3EventMessage(context, actual);
  if (guarded !== parsed.guardedMemo) throw new Error('fresh WTLOS guarded memo mismatch');
  return guarded;
}

/**
 * Reconstruct the two public-input arrays passed by r12 Parameters.sol. This
 * checks shape and root selection only. The caller must authenticate the
 * pre-state snapshot and provide a correct Keccak-256 implementation; it does
 * not validate either proof, the snapshot, or the EVM receipt.
 */
export function freshWTLOSV3VerifierInputs(
  context: FreshWTLOSV3MemoContext,
  source: FreshWTLOSV3CalldataSource,
  calldata: string,
  roots: FreshWTLOSV3RootSnapshot,
  keccak256RawMemo: (rawMemoHex: string) => string,
): FreshWTLOSV3VerifierInputs {
  const parsed = parseFreshWTLOSV3Calldata(context, source, calldata);
  const historical = roots.historical;
  const current = roots.current;
  if (historical.index !== parsed.transferIndex || historical.index < 0n ||
      current.index < 0n || historical.index % 128n !== 0n ||
      current.index % 128n !== 0n || historical.index > current.index ||
      current.index > MAX_SUCCESSFUL_PRE_TRANSACTION_INDEX) {
    throw new Error('fresh WTLOS root indices do not match the transaction');
  }
  for (const [label, root] of [['historical', historical.root], ['current', current.root]] as const) {
    if (root <= 0n || root >= FIELD_MODULUS) {
      throw new Error(`fresh WTLOS ${label} root is not canonical and nonzero`);
    }
  }
  const digest = hexBytes(keccak256RawMemo(`0x${parsed.rawMemo}`), 'raw memo Keccak-256');
  if (digest.length !== 32) throw new Error('raw memo Keccak-256 must be 32 bytes');
  const memoField = unsigned(digest) % FIELD_MODULUS;
  return {
    transfer: [historical.root, parsed.nullifier, parsed.outCommit,
      parsed.packedDeltaAndPoolId, memoField],
    tree: [current.root, parsed.nextRoot, parsed.outCommit],
  };
}
