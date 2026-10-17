/**
 * Source-only reconstruction of r12 roots from a complete, ordered sequence
 * of authenticated successful pool transactions and receipts. The sequence,
 * chain identity, deployed runtime, and final checkpoint remain caller trust
 * boundaries. This is not a proof of RPC authenticity or ZK soundness.
 */
import type { FreshWTLOSV3MemoContext } from './fresh-wtlos-v3-memo.js';
import { parseFreshWTLOSV3Calldata } from './fresh-wtlos-v3-calldata.js';
import { bindFreshWTLOSV3Receipt } from './fresh-wtlos-v3-receipt.js';
import type {
  FreshWTLOSV3BoundReceipt,
  FreshWTLOSV3ReceiptRecord,
  FreshWTLOSV3TransactionRecord,
} from './fresh-wtlos-v3-receipt.js';

// r12 ZkBobPoolWTLOSOnly.EMPTY_TREE_ROOT, not a claim of circuit identity.
const EMPTY_TREE_ROOT = 11469701942666298368112882412133877458305516134926649826543144744382391691533n;
const ZERO_HASH = `0x${'00'.repeat(32)}`;

export interface FreshWTLOSV3HistoryCheckpoint {
  currentIndex: bigint;
  currentRoot: bigint;
  allMessagesHash: string;
}

function normalizedHash(value: string): string {
  if (typeof value !== 'string') throw new Error('checkpoint hash must be hex');
  const raw = value.startsWith('0x') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error('checkpoint hash must be 32 bytes');
  return `0x${raw.toLowerCase()}`;
}

function trustedContext(context: FreshWTLOSV3MemoContext): FreshWTLOSV3MemoContext {
  if (context.format !== 'fresh-wtlos-v3' || context.chainId !== 40 ||
      typeof context.poolProxy !== 'string' ||
      !/^0x[0-9a-fA-F]{40}$/.test(context.poolProxy) ||
      /^0x0{40}$/i.test(context.poolProxy)) {
    throw new Error('fresh WTLOS history requires a trusted chain-40 pool route');
  }
  if (typeof context.poolId === 'number' && !Number.isSafeInteger(context.poolId)) {
    throw new Error('fresh WTLOS history pool ID is not a safe integer');
  }
  let poolId: bigint;
  try { poolId = BigInt(context.poolId); }
  catch { throw new Error('fresh WTLOS history pool ID is invalid'); }
  if (poolId <= 0n || poolId >= (1n << 24n)) throw new Error('fresh WTLOS history pool ID is out of range');
  return Object.freeze({ format: 'fresh-wtlos-v3', chainId: 40,
    poolId, poolProxy: context.poolProxy.toLowerCase() });
}

/**
 * Start only at the fresh pool's authenticated initialization state. To prove
 * replay completeness, compare the final checkpoint with separately trusted
 * chain state after the same finalized transaction. A prior-block snapshot
 * alone cannot account for multiple transactions in one block.
 */
export class FreshWTLOSV3HistoryReplay {
  private readonly context: FreshWTLOSV3MemoContext;
  private readonly roots = new Map<bigint, bigint>([[0n, EMPTY_TREE_ROOT]]);
  private currentIndex = 0n;
  private allMessagesHash = ZERO_HASH;
  private lastBlockNumber: bigint | undefined;
  private lastBlockHash: string | undefined;
  private lastTransactionIndex: bigint | undefined;

  constructor(context: FreshWTLOSV3MemoContext) {
    this.context = trustedContext(context);
  }

  public checkpoint(): FreshWTLOSV3HistoryCheckpoint {
    const currentRoot = this.roots.get(this.currentIndex);
    if (currentRoot === undefined) throw new Error('fresh WTLOS history current root is absent');
    return { currentIndex: this.currentIndex, currentRoot, allMessagesHash: this.allMessagesHash };
  }

  public assertCheckpoint(expected: FreshWTLOSV3HistoryCheckpoint): void {
    const actual = this.checkpoint();
    if (expected.currentIndex !== actual.currentIndex ||
        expected.currentRoot !== actual.currentRoot ||
        normalizedHash(expected.allMessagesHash) !== actual.allMessagesHash) {
      throw new Error('fresh WTLOS history checkpoint does not match trusted state');
    }
  }

  public advance(
    chainId: number,
    transaction: FreshWTLOSV3TransactionRecord,
    receipt: FreshWTLOSV3ReceiptRecord,
    keccak256Hex: (bytesHex: string) => string,
  ): FreshWTLOSV3BoundReceipt {
    const blockHash = normalizedHash(transaction.blockHash);
    if (this.lastBlockNumber !== undefined &&
        (transaction.blockNumber < this.lastBlockNumber ||
         (transaction.blockNumber === this.lastBlockNumber &&
          transaction.transactionIndex <= this.lastTransactionIndex!))) {
      throw new Error('fresh WTLOS history transaction order is not increasing');
    }
    if (transaction.blockNumber === this.lastBlockNumber && blockHash !== this.lastBlockHash) {
      throw new Error('fresh WTLOS same-block transactions disagree on block hash');
    }
    const parsed = parseFreshWTLOSV3Calldata(this.context,
      { chainId, to: transaction.to }, transaction.input);
    const historicalRoot = this.roots.get(parsed.transferIndex);
    const currentRoot = this.roots.get(this.currentIndex);
    if (historicalRoot === undefined || currentRoot === undefined) {
      throw new Error('fresh WTLOS history has a missing prior root');
    }
    const bound = bindFreshWTLOSV3Receipt(this.context, chainId, transaction, receipt,
      { historical: { index: parsed.transferIndex, root: historicalRoot },
        current: { index: this.currentIndex, root: currentRoot } },
      this.allMessagesHash, keccak256Hex);
    // Commit only after every receipt, memo, root and rolling-hash check passes.
    this.roots.set(bound.eventIndex, bound.parsed.nextRoot);
    this.currentIndex = bound.eventIndex;
    this.allMessagesHash = bound.allMessagesHash;
    this.lastBlockNumber = transaction.blockNumber;
    this.lastBlockHash = blockHash;
    this.lastTransactionIndex = transaction.transactionIndex;
    return bound;
  }
}
