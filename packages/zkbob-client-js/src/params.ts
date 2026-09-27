import { InternalError } from "./errors";
import { FileCache } from "./file-cache";
import { SnarkConfigParams } from "./config";
import sha256 from 'fast-sha256';

const MAX_VK_LOAD_ATTEMPTS = 3;
// Draft circuits PR8 identity. These pins label an offline byte inspection;
// they do not authenticate a browser module, key ceremony, or proof capability.
export const WTLOS_CIRCUIT_SOURCE_TREE = 'cde8d9501f3ade151299ac7c204fb22ffee07589';
export const WTLOS_TRANSFER_CIRCUIT_IDENTITY =
    '5b1bb02a9ff12b4beb86c2f8695d8c6e622ab73a821729134c280d90f0a4ea0a';
export const WTLOS_TREE_CIRCUIT_IDENTITY =
    '45c77c1a59970ff81f272041474627398ba93a47570b6dd9f440a9045b322610';

export enum LoadingStatus {
    NotStarted = 0,
    InProgress,
    Completed,
    Failed
}

// The class controls both the SNARK params and associated verification key
// You can initiate param/vk loading independently when needed
export class SnarkParams {
    private paramUrl: string;
    private vkUrl: string;
    private expectedParamsHash: string | undefined;
    private expectedVkHash: string | undefined;
    private expectedWTLOSCircuitSourceTree: string | undefined;

    private cache: FileCache;

    // params - wasm object (from binary), vk - json
    private params: any | undefined;
    private vk: any | undefined;
    
    // covers only params not vk
    private loadingPromise: Promise<any> | undefined;
    private loadingStatus: LoadingStatus;

    public constructor(params: SnarkConfigParams) {
        this.loadingStatus = LoadingStatus.NotStarted;
        this.paramUrl = params.transferParamsUrl;
        this.vkUrl = params.transferVkUrl;
        this.expectedParamsHash = this.checkedExpectedHash(params.transferParamsSha256, 'params');
        this.expectedVkHash = this.checkedExpectedHash(params.transferVkSha256, 'verification key');
        if (params.wtlosCircuitSourceTree !== undefined &&
            !/^[0-9a-fA-F]{40}$/.test(params.wtlosCircuitSourceTree)) {
            throw new InternalError('Invalid WTLOS circuit source tree');
        }
        this.expectedWTLOSCircuitSourceTree = params.wtlosCircuitSourceTree?.toLowerCase();
    }

    public async getParams(wasm: any, expectedHash?: string): Promise<any> {
        // Reject source-tagged WTLOS inputs before legacy WASM parsing. An
        // untagged configuration cannot be classified by this generic class.
        if (this.expectedWTLOSCircuitSourceTree) {
            throw new InternalError('Source-tagged WTLOS parameters cannot use the legacy parser');
        }
        const effectiveHash = this.resolveExpectedHash(expectedHash);
        if (!this.isParamsReady()) {
            this.loadParams(wasm, effectiveHash);
            return await this.loadingPromise;
        }

        return this.params;
    }

    // Inspect only caller-supplied bytes against configured hashes and the
    // PR8 source pin. No module is accepted, no key is parsed, and this receipt
    // must not be used as evidence of ceremony or browser-prover readiness.
    public async inspectWTLOSArtifactsFromBytes(
        paramsBytes: Uint8Array,
        vkBytes: Uint8Array
    ): Promise<Readonly<{
        status: 'INSPECTION_ONLY_NO_PROVER';
        authoritative: false;
        proverAvailable: false;
        sourceTree: string;
        transferCircuitIdentitySha256: string;
        treeCircuitIdentitySha256: string;
        parameterSha256: string;
        verificationKeySha256: string;
    }>> {
        if (arguments.length !== 2) {
            throw new InternalError('WTLOS artifact inspection accepts exactly two byte arrays');
        }
        const source = this.expectedWTLOSCircuitSourceTree;
        const paramsHash = this.expectedParamsHash;
        const vkHash = this.expectedVkHash;
        if (!source || !paramsHash || !vkHash) {
            throw new InternalError('WTLOS source, params, and VK hashes are required');
        }
        if (source !== WTLOS_CIRCUIT_SOURCE_TREE) {
            throw new InternalError('WTLOS circuit source is not the reviewed PR8 tree');
        }

        if (!(paramsBytes instanceof Uint8Array) || !(vkBytes instanceof Uint8Array) ||
            this.sha256Hex(paramsBytes) !== paramsHash ||
            this.sha256Hex(vkBytes) !== vkHash) {
            throw new InternalError('WTLOS parameter or VK byte hash mismatch');
        }
        let verificationKey: any;
        try {
            verificationKey = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(vkBytes));
        } catch {
            throw new InternalError('Invalid WTLOS verification key JSON');
        }
        if (!verificationKey || typeof verificationKey !== 'object' ||
            !['alpha', 'beta', 'gamma', 'delta', 'ic']
                .every(field => Array.isArray(verificationKey[field]))) {
            throw new InternalError('Invalid WTLOS verification key structure');
        }
        return Object.freeze({
            status: 'INSPECTION_ONLY_NO_PROVER' as const,
            authoritative: false as const,
            proverAvailable: false as const,
            sourceTree: source,
            transferCircuitIdentitySha256: WTLOS_TRANSFER_CIRCUIT_IDENTITY,
            treeCircuitIdentitySha256: WTLOS_TREE_CIRCUIT_IDENTITY,
            parameterSha256: paramsHash,
            verificationKeySha256: vkHash,
        });
    }

    // VKs are much smaller than params so we can refetch it in case any errors
    // VK doesn't stored at the local storage (no verification ability currently)
    public async getVk(): Promise<any> {
        let attempts = 0;
        const filename = this.vkUrl.substring(this.vkUrl.lastIndexOf('/') + 1);
        const startTs = Date.now();
        while (!this.isVkReady() && attempts++ < MAX_VK_LOAD_ATTEMPTS) {
          try {
            const response = await fetch(this.vkUrl, { headers: { 'Cache-Control': 'no-cache' } });
            if (!response.ok) throw new InternalError(`VK request failed with status ${response.status}`);
            const bytes = new Uint8Array(await response.arrayBuffer());
            if (this.expectedVkHash && this.sha256Hex(bytes) !== this.expectedVkHash) {
                throw new InternalError('Verification key hash mismatch');
            }
            const vk = JSON.parse(new TextDecoder().decode(bytes));
            // verify VK structure
            if (typeof vk === 'object' && vk !== null &&
                vk.hasOwnProperty('alpha') && Array.isArray(vk.alpha) &&
                vk.hasOwnProperty('beta') && Array.isArray(vk.beta) &&
                vk.hasOwnProperty('gamma') && Array.isArray(vk.gamma) &&
                vk.hasOwnProperty('delta') && Array.isArray(vk.delta) &&
                vk.hasOwnProperty('ic') && Array.isArray(vk.ic))
            {
                this.vk = vk;
            } else {
                throw new InternalError(`The object isn't a valid VK`);
            }

            this.vk = vk;

            console.log(`VK ${filename} loaded in ${Date.now() - startTs} ms`);
          } catch(err) {
            console.warn(`VK loading attempt has failed: ${err.message}`);
          }
        }

        if (!this.isVkReady()) {
            throw new InternalError(`Cannot load a valid VK after ${MAX_VK_LOAD_ATTEMPTS} attempts`);
        }

        return this.vk;
      }

    private loadParams(wasm: any, expectedHash?: string) {
        if (this.isParamsReady() || this.loadingStatus == LoadingStatus.InProgress) {
            return;
        }

        this.loadingStatus = LoadingStatus.InProgress;
        this.loadingPromise = new Promise(async (resolve, reject) => {
            try {
                const cache = await this.fileCache();

                console.time(`Load parameters from DB`);
                let txParamsData = await cache.get(this.paramUrl)
                    .finally(() => console.timeEnd(`Load parameters from DB`));

                // check parameters hash if needed
                if (txParamsData && expectedHash !== undefined) {
                    // Hash the retrieved bytes. The IndexedDB hash record is a
                    // cache hint written separately and is not trusted for the
                    // WTLOS release boundary.
                    const cachedHash = await cache.calcHash(txParamsData);
                    if (cachedHash.toLowerCase() != expectedHash.toLowerCase()) {
                        // forget saved params in case of hash inconsistence
                        console.warn(`Hash of cached tx params (${cachedHash}) doesn't associated with provided (${this.paramUrl}).`);
                        await cache.remove(this.paramUrl);
                        txParamsData = null;
                    }
                }

                let params;
                if (!txParamsData) {
                    console.time(`Download params`);
                    txParamsData = await cache.cache(this.paramUrl)
                        .finally(() => console.timeEnd(`Download params`));

                    if (expectedHash !== undefined) {
                        const downloadedHash = await cache.calcHash(txParamsData);
                        if (downloadedHash.toLowerCase() !== expectedHash) {
                            await cache.remove(this.paramUrl);
                            throw new InternalError('Downloaded transaction params hash mismatch');
                        }
                    }

                    try {
                        console.time(`Creating Params object`);
                        params = wasm.Params.fromBinary(new Uint8Array(txParamsData!));
                    } finally {
                        console.timeEnd(`Creating Params object`);
                    }
                } else {
                    console.log(`File ${this.paramUrl} is present in cache, no need to fetch`);

                    try {
                        console.time(`Creating Params object`);
                        params = wasm.Params.fromBinaryExtended(new Uint8Array(txParamsData!), false, false, false);
                    } finally {
                        console.timeEnd(`Creating Params object`);
                    }
                }
                resolve(params);
            } catch (err) {
                reject(new InternalError(`Failed to load params: ${err.message}`));
            }
        }).then((params) => {
            this.params = params;
            this.loadingStatus = LoadingStatus.Completed;
            return params;
        }, (err) => {
            this.params = undefined;
            this.loadingStatus = LoadingStatus.Failed;
            throw err;
        })
    }

    private isParamsReady(): boolean {
        return this.params !== undefined;
    }

    private isVkReady(): boolean {
        return this.vk !== undefined;
    }

    private checkedExpectedHash(value: string | undefined, name: string): string | undefined {
        if (value === undefined) return undefined;
        if (!/^[0-9a-fA-F]{64}$/.test(value)) {
            throw new InternalError(`Invalid expected ${name} SHA-256`);
        }
        return value.toLowerCase();
    }

    private resolveExpectedHash(value: string | undefined): string | undefined {
        const requested = this.checkedExpectedHash(value, 'params');
        if (this.expectedParamsHash && requested && this.expectedParamsHash !== requested) {
            throw new InternalError('Conflicting transaction params hashes');
        }
        return this.expectedParamsHash ?? requested;
    }

    private sha256Hex(data: Uint8Array): string {
        return [...sha256(data)].map(x => x.toString(16).padStart(2, '0')).join('');
    }

    private async fileCache(): Promise<FileCache> {
        if (!this.cache) {
            this.cache = await FileCache.init();
        }

        return this.cache;
    }

    public wtlosCircuitSourceTree(): string | undefined {
        return this.expectedWTLOSCircuitSourceTree;
    }
}
