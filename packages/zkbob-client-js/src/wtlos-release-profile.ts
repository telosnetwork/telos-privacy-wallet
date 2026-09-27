import sha256 from 'fast-sha256';
import { InternalError } from './errors';

export const WTLOS_ONLY_RELEASE_SCHEMA = 'telos-wtlos-only-release-v1';
export const WTLOS_ONLY_RELEASE_HEADER = 'x-wtlos-release-profile-sha256';
export const WTLOS_ONLY_MEMO_DOMAIN = 'TPD1';
export const WTLOS_ONLY_TRANSACT_SELECTOR = '0xaf989083';
export const WTLOS_TOKEN = '0xD102cE6A4dB07D247fcc28F366A623Df0938CA9E';

export interface WTLOSReleaseProfile {
  schema: typeof WTLOS_ONLY_RELEASE_SCHEMA;
  chainId: 40;
  poolAddress: string;
  poolId: string;
  tokenAddress: string;
  memoDomain: typeof WTLOS_ONLY_MEMO_DOMAIN;
  transactSelector: typeof WTLOS_ONLY_TRANSACT_SELECTOR;
  circuitSourceTree: string;
  contractSourceTree: string;
  ceremonyManifestSha256: string;
  implementationAddress: string;
  proxyCodeHash: string;
  implementationCodeHash: string;
  transferParamsSha256: string;
  transferVkSha256: string;
  declaredRelayerCommit: string;
}

const SHA256 = /^[0-9a-f]{64}$/;
const GIT_TREE = /^[0-9a-f]{40}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const EVM_HASH = /^0x[0-9a-fA-F]{64}$/;

function isHex(value: unknown, pattern: RegExp): value is string {
  return typeof value === 'string' && pattern.test(value);
}

export function canonicalWTLOSReleaseProfile(value: any): WTLOSReleaseProfile {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      value.schema !== WTLOS_ONLY_RELEASE_SCHEMA || value.chainId !== 40 ||
      value.memoDomain !== WTLOS_ONLY_MEMO_DOMAIN ||
      value.transactSelector !== WTLOS_ONLY_TRANSACT_SELECTOR ||
      !ADDRESS.test(value.poolAddress) || !ADDRESS.test(value.tokenAddress) ||
      value.tokenAddress.toLowerCase() !== WTLOS_TOKEN.toLowerCase() ||
      typeof value.poolId !== 'string' || !/^[1-9][0-9]*$/.test(value.poolId) ||
      BigInt(value.poolId) > 0xffffffn ||
      !isHex(value.circuitSourceTree, GIT_TREE) ||
      !isHex(value.contractSourceTree, GIT_TREE) ||
      !isHex(value.ceremonyManifestSha256, SHA256) ||
      !isHex(value.implementationAddress, ADDRESS) ||
      !isHex(value.proxyCodeHash, EVM_HASH) ||
      !isHex(value.implementationCodeHash, EVM_HASH) ||
      !isHex(value.transferParamsSha256, SHA256) ||
      !isHex(value.transferVkSha256, SHA256) ||
      !isHex(value.declaredRelayerCommit, GIT_TREE)) {
    throw new InternalError('Invalid WTLOS-only release profile');
  }
  return {
    schema: WTLOS_ONLY_RELEASE_SCHEMA,
    chainId: 40,
    poolAddress: value.poolAddress.toLowerCase(),
    poolId: value.poolId,
    tokenAddress: WTLOS_TOKEN,
    memoDomain: WTLOS_ONLY_MEMO_DOMAIN,
    transactSelector: WTLOS_ONLY_TRANSACT_SELECTOR,
    circuitSourceTree: value.circuitSourceTree.toLowerCase(),
    contractSourceTree: value.contractSourceTree.toLowerCase(),
    ceremonyManifestSha256: value.ceremonyManifestSha256.toLowerCase(),
    implementationAddress: value.implementationAddress.toLowerCase(),
    proxyCodeHash: value.proxyCodeHash.toLowerCase(),
    implementationCodeHash: value.implementationCodeHash.toLowerCase(),
    transferParamsSha256: value.transferParamsSha256.toLowerCase(),
    transferVkSha256: value.transferVkSha256.toLowerCase(),
    declaredRelayerCommit: value.declaredRelayerCommit.toLowerCase(),
  };
}

export function wtlosReleaseProfileDigest(value: WTLOSReleaseProfile): string {
  const canonical = canonicalWTLOSReleaseProfile(value);
  const bytes = new TextEncoder().encode(JSON.stringify(canonical));
  return [...sha256(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
}

export function assertWTLOSReleaseProfileMatches(actual: unknown, expected: WTLOSReleaseProfile): string {
  const actualCanonical = canonicalWTLOSReleaseProfile(actual);
  const expectedCanonical = canonicalWTLOSReleaseProfile(expected);
  const actualDigest = wtlosReleaseProfileDigest(actualCanonical);
  const expectedDigest = wtlosReleaseProfileDigest(expectedCanonical);
  if (actualDigest !== expectedDigest) {
    throw new InternalError('WTLOS-only relayer release profile mismatch');
  }
  return expectedDigest;
}
