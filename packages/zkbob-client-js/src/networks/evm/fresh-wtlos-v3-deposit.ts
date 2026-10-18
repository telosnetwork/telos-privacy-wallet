/**
 * Source-only bridge from the guarded prover statement to one signed deposit
 * call. Neither opaque proof is verified here. The caller must authenticate
 * the pool route, pre-transaction roots, and prover output independently.
 */
import {
  buildFreshWTLOSV3IntentFromTransaction,
  signFreshWTLOSV3Transaction,
  type FreshWTLOSV3SignedIntent,
  type FreshWTLOSV3SigningBackend,
  type FreshWTLOSV3TransactionData,
  type UIntInput,
} from '../../signers/fresh-wtlos-v3-intent.js';
import type { FreshWTLOSV3MemoContext } from './fresh-wtlos-v3-memo.js';
import {
  assembleFreshWTLOSV3Calldata,
  freshWTLOSV3VerifierInputs,
  type FreshWTLOSV3CalldataAssembly,
  type FreshWTLOSV3RootSnapshot,
  type FreshWTLOSV3VerifierInputs,
} from './fresh-wtlos-v3-calldata.js';

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PLACEHOLDER_SIGNATURE = `${'00'.repeat(31)}01${'00'.repeat(31)}01`;

export type FreshWTLOSV3DepositProofFields = Pick<FreshWTLOSV3CalldataAssembly,
  'transferIndex' | 'energyAmount' | 'transferTokenDelta' | 'transferProof' |
  'nextRoot' | 'treeProof'>;

export interface FreshWTLOSV3SignedDeposit {
  calldata: string;
  verifierInputs: FreshWTLOSV3VerifierInputs;
  signedIntent: FreshWTLOSV3SignedIntent;
}

function sameInputs(actual: readonly bigint[], expected: readonly bigint[], label: string): void {
  if (actual.length !== expected.length || actual.some((value, i) => value !== expected[i])) {
    throw new Error(`fresh WTLOS ${label} statement does not match calldata`);
  }
}

/**
 * Preflight the exact public inputs before requesting a signature, then sign
 * an immutable snapshot and assemble the final call from that same snapshot.
 * treePublic is the separately supplied tree prover statement, not a proof
 * verification result. The real integration must qualify both proofs and
 * authenticate the pre-state roots before broadcasting.
 */
export async function assembleSignedFreshWTLOSV3Deposit(
  context: FreshWTLOSV3MemoContext,
  roots: FreshWTLOSV3RootSnapshot,
  tx: FreshWTLOSV3TransactionData,
  treePublic: readonly [bigint, bigint, bigint],
  proofFields: FreshWTLOSV3DepositProofFields,
  expectedDepositor: string,
  deadline: UIntInput,
  operator: string,
  keccak256HexBytes: (rawHex: string) => string,
  backend: FreshWTLOSV3SigningBackend,
  signatureCallback: (request: { type: 1; data: any }) => Promise<string>,
  nowSeconds?: () => number,
): Promise<FreshWTLOSV3SignedDeposit> {
  // Capture every caller-owned object before any awaited wallet callback.
  const route = { format: context.format, chainId: context.chainId,
    poolId: context.poolId, poolProxy: context.poolProxy };
  const source = { chainId: route.chainId, to: route.poolProxy };
  const snapshot: FreshWTLOSV3TransactionData = {
    public: { ...tx.public }, memo: tx.memo,
  };
  const rootSnapshot = {
    historical: { ...roots.historical }, current: { ...roots.current },
  };
  const treeStatement: [bigint, bigint, bigint] = [...treePublic];
  const fields = { ...proofFields };
  const prepared = buildFreshWTLOSV3IntentFromTransaction(
    snapshot, route.chainId, route.poolProxy, route.poolId,
    deadline, operator, keccak256HexBytes,
  );
  const message = prepared.typedData.message;
  const signedMemoDigest = message.memoDataHash.toLowerCase();
  const stableKeccak = (rawHex: string): string => {
    if (rawHex.toLowerCase() !== prepared.rawMemo) {
      throw new Error('fresh WTLOS raw memo changed after preflight');
    }
    const digest = keccak256HexBytes(rawHex);
    if (typeof digest !== 'string' || !/^(?:0x)?[0-9a-fA-F]{64}$/.test(digest)) {
      throw new Error('fresh WTLOS memo digest is not 32-byte hex');
    }
    const normalized = `0x${(digest.startsWith('0x') ? digest.slice(2) : digest).toLowerCase()}`;
    if (normalized !== signedMemoDigest) {
      throw new Error('fresh WTLOS full memo digest changed after preflight');
    }
    return normalized;
  };
  const base: FreshWTLOSV3CalldataAssembly = {
    ...fields, txType: '0000', nullifier: BigInt(message.nullifier),
    outCommit: BigInt(message.outCommit), rawMemo: prepared.rawMemo,
    deadline: prepared.deadline, compactSignature: PLACEHOLDER_SIGNATURE,
  };
  const preview = assembleFreshWTLOSV3Calldata(route, source, base);
  const expectedTransfer: [bigint, bigint, bigint, bigint, bigint] = [
    BigInt(message.root), BigInt(message.nullifier), BigInt(message.outCommit),
    BigInt(message.packedDeltaAndPoolId), BigInt(message.memoDataHash) % FIELD_MODULUS,
  ];
  const previewInputs = freshWTLOSV3VerifierInputs(
    route, source, preview, rootSnapshot, stableKeccak,
  );
  sameInputs(previewInputs.transfer, expectedTransfer, 'transfer');
  sameInputs(previewInputs.tree, treeStatement, 'tree');

  const signedIntent = await signFreshWTLOSV3Transaction(
    snapshot, route.poolProxy, route.poolId, expectedDepositor,
    prepared.deadline, operator, stableKeccak,
    backend, signatureCallback, nowSeconds,
  );
  if (JSON.stringify(signedIntent.typedData) !== JSON.stringify(prepared.typedData) ||
      signedIntent.rawMemo !== prepared.rawMemo || signedIntent.deadline !== prepared.deadline) {
    throw new Error('fresh WTLOS signed statement changed after preflight');
  }
  const calldata = assembleFreshWTLOSV3Calldata(route, source, {
    ...base, compactSignature: signedIntent.compactSignature,
  });
  const verifierInputs = freshWTLOSV3VerifierInputs(
    route, source, calldata, rootSnapshot, stableKeccak,
  );
  sameInputs(verifierInputs.transfer, expectedTransfer, 'signed transfer');
  sameInputs(verifierInputs.tree, treeStatement, 'signed tree');
  return { calldata, verifierInputs, signedIntent };
}
