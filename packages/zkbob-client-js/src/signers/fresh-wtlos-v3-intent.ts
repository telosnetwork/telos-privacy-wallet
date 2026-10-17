/**
 * The fresh WTLOS pool's type-0 intent. This is deliberately separate from
 * ApproveSigner: legacy pools continue to sign only their nullifier.
 *
 * Call this only after the final proof public inputs, memo, fee and operator
 * have been selected. The caller must use the returned rawMemo unchanged in
 * calldata and supply a Keccak-256 implementation that hashes hex as bytes.
 */

const BN254_SCALAR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const UINT64_MAX = (1n << 64n) - 1n;
const COMPACT_S_MASK = (1n << 255n) - 1n;
const DEPOSIT_MEMO_MIN_BYTES = 8 + 4 + 4 + 20;
const DEPOSIT_MEMO_TAG = '54504431'; // TPD1

export type UIntInput = bigint | string | number;

export interface FreshWTLOSV3IntentInput {
  chainId: UIntInput;
  poolProxy: string;
  root: UIntInput;
  nullifier: UIntInput;
  outCommit: UIntInput;
  packedDeltaAndPoolId: UIntInput;
  rawMemo: string;
  deadline: UIntInput;
  operator: string;
}

/** The exact fields serialized by the existing wasm TransactionData.public. */
export interface FreshWTLOSV3TransactionData {
  public: {
    root: UIntInput;
    nullifier: UIntInput;
    out_commit: UIntInput;
    delta: UIntInput;
    memo: UIntInput;
  };
  memo: string;
}

/** Narrow wallet boundary; the existing NetworkBackend implements these methods. */
export interface FreshWTLOSV3SigningBackend {
  getChainId(): Promise<number>;
  toCompactSignature(signature: string): string;
  recoverSignerTypedData(typedData: any, signature: string): Promise<string>;
}

export interface FreshWTLOSV3SignedIntent {
  rawMemo: string;
  deadline: bigint;
  compactSignature: string;
  memoAndSignature: string;
  typedData: ReturnType<typeof buildFreshWTLOSV3Intent>['typedData'];
}

function uint(value: UIntInput, label: string, maximum: bigint): bigint {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) {
    throw new Error(`${label} must be a nonnegative safe integer, bigint or integer string`);
  }
  if (typeof value === 'string' && !/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) {
    throw new Error(`${label} must be an unsigned integer string`);
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > maximum) throw new Error(`${label} is out of range`);
  return parsed;
}

function hex(value: string, label: string, bytes?: number): string {
  if (!/^(?:0x)?[0-9a-fA-F]*$/.test(value)) throw new Error(`${label} is not hex`);
  const raw = value.startsWith('0x') ? value.slice(2) : value;
  if (raw.length % 2 !== 0 || (bytes !== undefined && raw.length !== bytes * 2)) {
    throw new Error(`${label} has the wrong byte length`);
  }
  return `0x${raw.toLowerCase()}`;
}

function address(value: string, label: string): string {
  const normalized = hex(value, label, 20);
  if (normalized === `0x${'0'.repeat(40)}`) throw new Error(`${label} cannot be zero`);
  return normalized;
}

function cloneTypedData<T>(value: T): T {
  // This statement contains only plain objects, arrays and strings. Clone at
  // the callback boundary so it cannot retain an alias to the trusted copy.
  return JSON.parse(JSON.stringify(value)) as T;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function buildFreshWTLOSV3Intent(
  input: FreshWTLOSV3IntentInput,
  keccak256HexBytes: (rawHex: string) => string,
) {
  const chainId = uint(input.chainId, 'chainId', (1n << 256n) - 1n);
  if (chainId === 0n) throw new Error('chainId cannot be zero');
  const poolProxy = address(input.poolProxy, 'poolProxy');
  const operator = address(input.operator, 'operator');
  const root = uint(input.root, 'root', BN254_SCALAR_MODULUS - 1n);
  const nullifier = uint(input.nullifier, 'nullifier', BN254_SCALAR_MODULUS - 1n);
  const outCommit = uint(input.outCommit, 'outCommit', BN254_SCALAR_MODULUS - 1n);
  const packedDeltaAndPoolId = uint(
    input.packedDeltaAndPoolId, 'packedDeltaAndPoolId', BN254_SCALAR_MODULUS - 1n,
  );
  const deadline = uint(input.deadline, 'deadline', UINT64_MAX);
  if (deadline === 0n) throw new Error('deadline cannot be zero');
  const rawMemo = hex(input.rawMemo, 'rawMemo');
  const memoBytes = (rawMemo.length - 2) / 2;
  if (memoBytes < DEPOSIT_MEMO_MIN_BYTES || memoBytes > 65535) {
    throw new Error('deposit rawMemo length is out of range');
  }
  const memo = rawMemo.slice(2);
  const messagePrefix = BigInt(`0x${memo.slice(16, 24)}`);
  if ((messagePrefix & 0xffffn) !== 0n ||
      memo.slice(24, 32) !== DEPOSIT_MEMO_TAG ||
      memo.slice(32, 72) !== poolProxy.slice(2)) {
    throw new Error('deposit rawMemo pool domain mismatch');
  }
  const tokenBits = packedDeltaAndPoolId & ((1n << 64n) - 1n);
  const tokenAmount = tokenBits >= (1n << 63n) ? tokenBits - (1n << 64n) : tokenBits;
  const energyBits = (packedDeltaAndPoolId >> 64n) & ((1n << 112n) - 1n);
  if (tokenAmount <= 0n || energyBits !== 0n) {
    throw new Error('deposit public delta is not WTLOS-only');
  }
  const memoDataHash = hex(keccak256HexBytes(rawMemo), 'memoDataHash', 32);

  return {
    rawMemo,
    deadline,
    operator,
    typedData: {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        DepositAuthorization: [
          { name: 'root', type: 'uint256' },
          { name: 'nullifier', type: 'uint256' },
          { name: 'outCommit', type: 'uint256' },
          { name: 'packedDeltaAndPoolId', type: 'uint256' },
          { name: 'memoDataHash', type: 'bytes32' },
          { name: 'deadline', type: 'uint64' },
          { name: 'operator', type: 'address' },
        ],
      },
      primaryType: 'DepositAuthorization',
      domain: {
        name: 'Telos Privacy WTLOS Deposit',
        version: '3',
        chainId: chainId.toString(),
        verifyingContract: poolProxy,
      },
      message: {
        root: root.toString(),
        nullifier: nullifier.toString(),
        outCommit: outCommit.toString(),
        packedDeltaAndPoolId: `0x${packedDeltaAndPoolId.toString(16).padStart(64, '0')}`,
        memoDataHash,
        deadline: deadline.toString(),
        operator,
      },
    },
  };
}

/**
 * Bind the signer request to the actual prover statement, rather than to
 * manually re-entered values. The proof's memo input is Keccak(raw memo)
 * reduced to BN254 Fr; the typed signature binds the full 256-bit hash.
 */
export function buildFreshWTLOSV3IntentFromTransaction(
  tx: FreshWTLOSV3TransactionData,
  chainId: UIntInput,
  poolProxy: string,
  expectedPoolId: UIntInput,
  deadline: UIntInput,
  operator: string,
  keccak256HexBytes: (rawHex: string) => string,
) {
  const poolId = uint(expectedPoolId, 'expectedPoolId', (1n << 24n) - 1n);
  const packed = uint(tx.public.delta, 'public.delta', BN254_SCALAR_MODULUS - 1n);
  if (packed >> 224n !== poolId) throw new Error('public.delta pool ID mismatch');
  const intent = buildFreshWTLOSV3Intent({
    chainId,
    poolProxy,
    root: tx.public.root,
    nullifier: tx.public.nullifier,
    outCommit: tx.public.out_commit,
    packedDeltaAndPoolId: packed,
    rawMemo: tx.memo,
    deadline,
    operator,
  }, keccak256HexBytes);
  const proofMemo = uint(tx.public.memo, 'public.memo', BN254_SCALAR_MODULUS - 1n);
  if (BigInt(intent.typedData.message.memoDataHash) % BN254_SCALAR_MODULUS !== proofMemo) {
    throw new Error('public.memo does not match raw memo bytes');
  }
  return intent;
}

/** Exact bytes after the 644-byte prefix for a fresh type-0 transact call. */
export function freshWTLOSV3MemoAndSignature(
  rawMemo: string, deadlineValue: UIntInput, compactSignature: string,
): string {
  const memo = hex(rawMemo, 'rawMemo');
  if ((memo.length - 2) / 2 < DEPOSIT_MEMO_MIN_BYTES || (memo.length - 2) / 2 > 65535) {
    throw new Error('rawMemo length is out of range');
  }
  const deadline = uint(deadlineValue, 'deadline', UINT64_MAX);
  if (deadline === 0n) throw new Error('deadline cannot be zero');
  const signature = hex(compactSignature, 'compactSignature', 64);
  const r = BigInt(`0x${signature.slice(2, 66)}`);
  const vs = BigInt(`0x${signature.slice(66)}`);
  const s = vs & COMPACT_S_MASK;
  if (r === 0n || r >= SECP256K1_ORDER || s === 0n || s > SECP256K1_ORDER / 2n) {
    throw new Error('compactSignature is not canonical');
  }
  return `${memo}${deadline.toString(16).padStart(16, '0')}${signature.slice(2)}`;
}

/**
 * Request the exact v3 typed statement and reject a signature from a different
 * depositor. The caller must still prove and submit these captured public
 * inputs and memo unchanged; this function does not select a running pool.
 */
export async function signFreshWTLOSV3Transaction(
  tx: FreshWTLOSV3TransactionData,
  poolProxy: string,
  expectedPoolId: UIntInput,
  expectedDepositor: string,
  deadlineValue: UIntInput,
  operator: string,
  keccak256HexBytes: (rawHex: string) => string,
  backend: FreshWTLOSV3SigningBackend,
  signatureCallback: (request: { type: 1; data: any }) => Promise<string>,
  nowSeconds: () => number = () => Math.floor(Date.now() / 1000),
): Promise<FreshWTLOSV3SignedIntent> {
  const chainId = await backend.getChainId();
  if (chainId !== 40) throw new Error('fresh WTLOS pool requires Telos EVM chain 40');
  const depositor = address(expectedDepositor, 'expectedDepositor');
  const intent = buildFreshWTLOSV3IntentFromTransaction(
    tx, chainId, poolProxy, expectedPoolId, deadlineValue, operator, keccak256HexBytes,
  );
  const now = uint(nowSeconds(), 'nowSeconds', UINT64_MAX);
  if (intent.deadline <= now) throw new Error('deposit authorization deadline has passed');

  // SignatureType.TypedDataV4 is 1 in the existing signer interface.
  const requestStatement = cloneTypedData(intent.typedData);
  const statementSnapshot = JSON.stringify(requestStatement);
  const returnedSignature = await signatureCallback({ type: 1, data: requestStatement });
  if (JSON.stringify(requestStatement) !== statementSnapshot) {
    throw new Error('v3 typed statement changed during signing');
  }
  const compactSignature = hex(
    backend.toCompactSignature(returnedSignature), 'compactSignature', 64,
  );
  const memoAndSignature = freshWTLOSV3MemoAndSignature(
    intent.rawMemo, intent.deadline, compactSignature,
  );
  const recovered = address(
    await backend.recoverSignerTypedData(intent.typedData, compactSignature), 'recoveredDepositor',
  );
  if (recovered !== depositor) throw new Error('v3 signature does not match depositor');
  if (intent.deadline <= uint(nowSeconds(), 'nowSeconds', UINT64_MAX)) {
    throw new Error('deposit authorization expired during signing');
  }
  return {
    rawMemo: intent.rawMemo,
    deadline: intent.deadline,
    compactSignature,
    memoAndSignature,
    typedData: deepFreeze(cloneTypedData(intent.typedData)),
  };
}
