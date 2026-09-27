const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const ts = require('typescript');

// Exercise the draft SnarkParams source without a browser, network,
// proving key, signer, wallet, or relayer. All bytes here are synthetic.
const sourcePath = path.join(__dirname, '../src/params.ts');
const compiled = ts.transpileModule(fs.readFileSync(sourcePath, 'utf8'), {
  compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
    esModuleInterop: true},
  fileName: sourcePath,
  reportDiagnostics: true,
});
assert.deepEqual(compiled.diagnostics, []);
const testedExports = {};
const digest = bytes => crypto.createHash('sha256').update(bytes).digest();
vm.runInNewContext(compiled.outputText, {
  exports: testedExports,
  require: name => {
    if (name === './errors') return {InternalError: Error};
    if (name === './file-cache') return {FileCache: {init: () => {
      throw new Error('cache must not be touched');
    }}};
    if (name === 'fast-sha256') return bytes => new Uint8Array(digest(bytes));
    throw new Error(`unexpected import: ${name}`);
  },
  TextDecoder,
  Uint8Array,
  console: {warn() {}, log() {}, time() {}, timeEnd() {}},
}, {timeout: 2000});
const {SnarkParams} = testedExports;

const tree = 'cde8d9501f3ade151299ac7c204fb22ffee07589';
const oldTree = '7a22196e1d4a791b452a6140bdfa915298f3f1da';
const transferIdentity = '5b1bb02a9ff12b4beb86c2f8695d8c6e622ab73a821729134c280d90f0a4ea0a';
const treeIdentity = '45c77c1a59970ff81f272041474627398ba93a47570b6dd9f440a9045b322610';
const key = Uint8Array.from([1, 2, 3, 4]);
const vk = new TextEncoder().encode(JSON.stringify({
  alpha: [], beta: [], gamma: [], delta: [], ic: [],
}));
const sha = bytes => digest(bytes).toString('hex');
const config = (paramsBytes = key, vkBytes = vk) => ({
  transferParamsUrl: 'https://example.invalid/unused-key',
  transferVkUrl: 'https://example.invalid/unused-vk',
  transferParamsSha256: sha(paramsBytes),
  transferVkSha256: sha(vkBytes),
  wtlosCircuitSourceTree: tree,
});
test('matching synthetic bytes produce a frozen, explicitly non-prover PR8 inspection receipt', async () => {
  assert.equal(testedExports.WTLOS_CIRCUIT_SOURCE_TREE, tree);
  assert.equal(testedExports.WTLOS_TRANSFER_CIRCUIT_IDENTITY, transferIdentity);
  assert.equal(testedExports.WTLOS_TREE_CIRCUIT_IDENTITY, treeIdentity);
  const params = new SnarkParams(config());
  const receipt = await params.inspectWTLOSArtifactsFromBytes(key, vk);
  assert.equal(Object.isFrozen(receipt), true);
  assert.equal(receipt.status, 'INSPECTION_ONLY_NO_PROVER');
  assert.equal(receipt.authoritative, false);
  assert.equal(receipt.proverAvailable, false);
  assert.equal(receipt.sourceTree, tree);
  assert.equal(receipt.transferCircuitIdentitySha256, transferIdentity);
  assert.equal(receipt.treeCircuitIdentitySha256, treeIdentity);
  assert.equal(receipt.parameterSha256, sha(key));
  assert.equal(receipt.verificationKeySha256, sha(vk));
  assert.equal('params' in receipt, false);
  assert.equal('verificationKey' in receipt, false);
  let legacyCalls = 0;
  await assert.rejects(params.getParams({Params: {fromBinary: () => {
    legacyCalls++;
  }}}), /Source-tagged WTLOS parameters cannot use the legacy parser/);
  assert.equal(legacyCalls, 0);
});

test('inspection rejects old source, changed bytes, and a caller-supplied module', async () => {
  const params = new SnarkParams(config());
  const staleConfig = new SnarkParams({...config(), wtlosCircuitSourceTree: oldTree});
  await assert.rejects(staleConfig.inspectWTLOSArtifactsFromBytes(key, vk),
    /reviewed PR8 tree/);
  await assert.rejects(params.inspectWTLOSArtifactsFromBytes(
    Uint8Array.from([1, 2, 3, 5]), vk), /byte hash mismatch/);
  await assert.rejects(params.inspectWTLOSArtifactsFromBytes(
    key, Uint8Array.from([0])), /byte hash mismatch/);
  let parserCalls = 0;
  const hostileModule = {WTLOSBrowserParams: {fromBinary: () => { parserCalls++; }}};
  await assert.rejects(params.inspectWTLOSArtifactsFromBytes(key, vk, hostileModule),
    /exactly two byte arrays/);
  await assert.rejects(params.inspectWTLOSArtifactsFromBytes(hostileModule, vk),
    /byte hash mismatch/);
  assert.equal(parserCalls, 0);
});

test('inspection requires complete pins and valid VK JSON', async () => {
  const partial = new SnarkParams({...config(), transferVkSha256: undefined});
  await assert.rejects(partial.inspectWTLOSArtifactsFromBytes(key, vk),
    /source, params, and VK hashes are required/);

  for (const bytes of [new TextEncoder().encode('not-json'),
    new TextEncoder().encode('{}')]) {
    const params = new SnarkParams(config(key, bytes));
    await assert.rejects(params.inspectWTLOSArtifactsFromBytes(key, bytes),
      /verification key/);
  }
});
