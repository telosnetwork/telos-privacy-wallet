const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const ts = require('typescript');

// Exercise the actual shipped SnarkParams source without a browser, network,
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
function moduleFor(hash = sha(key), source = tree,
  transfer = transferIdentity, treeUpdate = treeIdentity) {
  const calls = {parse: 0};
  return {
    calls,
    module: {WTLOSBrowserParams: {
      sourceTree: () => source,
      transferCircuitIdentitySha256: () => transfer,
      treeCircuitIdentitySha256: () => treeUpdate,
      parameterSha256: () => hash,
      fromBinary: bytes => { calls.parse++; return {byteLength: bytes.length}; },
    }},
  };
}

test('matching PR8 source, identities, key, and VK reach only the distinct WTLOS parser', async () => {
  assert.equal(testedExports.WTLOS_CIRCUIT_SOURCE_TREE, tree);
  assert.equal(testedExports.WTLOS_TRANSFER_CIRCUIT_IDENTITY, transferIdentity);
  assert.equal(testedExports.WTLOS_TREE_CIRCUIT_IDENTITY, treeIdentity);
  const params = new SnarkParams(config());
  const {calls, module} = moduleFor();
  const loaded = await params.loadWTLOSArtifactsFromBytes(module, key, vk);
  assert.equal(calls.parse, 1);
  assert.equal(loaded.params.byteLength, key.length);
  assert.deepEqual(Object.keys(loaded.verificationKey).sort(),
    ['alpha', 'beta', 'delta', 'gamma', 'ic']);
  await assert.rejects(params.getParams({Params: {fromBinary: () => {
    throw new Error('legacy parser reached');
  }}}), /source-bound browser loader/);
});

test('WTLOS loader rejects old source, identities, module claim, and changed bytes before parsing', async () => {
  const params = new SnarkParams(config());
  for (const {module, calls} of [
    moduleFor(sha(key), oldTree),
    moduleFor('f'.repeat(64)),
    moduleFor(sha(key), tree, '0'.repeat(64)),
    moduleFor(sha(key), tree, transferIdentity, '0'.repeat(64)),
    {module: {UnsafeStage0Params: moduleFor().module.WTLOSBrowserParams}, calls: {parse: 0}},
  ]) {
    await assert.rejects(params.loadWTLOSArtifactsFromBytes(module, key, vk));
    assert.equal(calls.parse, 0);
  }
  const staleConfig = new SnarkParams({...config(), wtlosCircuitSourceTree: oldTree});
  await assert.rejects(staleConfig.loadWTLOSArtifactsFromBytes(moduleFor().module, key, vk),
    /reviewed PR8 tree/);
  const {module, calls} = moduleFor();
  await assert.rejects(params.loadWTLOSArtifactsFromBytes(module,
    Uint8Array.from([1, 2, 3, 5]), vk), /byte hash mismatch/);
  await assert.rejects(params.loadWTLOSArtifactsFromBytes(module,
    key, Uint8Array.from([0])), /byte hash mismatch/);
  assert.equal(calls.parse, 0);
});

test('WTLOS loader requires complete pins and valid VK JSON before parsing', async () => {
  const partial = new SnarkParams({...config(), transferVkSha256: undefined});
  const {module} = moduleFor();
  await assert.rejects(partial.loadWTLOSArtifactsFromBytes(module, key, vk),
    /source, params, and VK hashes are required/);

  for (const bytes of [new TextEncoder().encode('not-json'),
    new TextEncoder().encode('{}')]) {
    const params = new SnarkParams(config(key, bytes));
    const {module: matching, calls} = moduleFor();
    await assert.rejects(params.loadWTLOSArtifactsFromBytes(matching, key, bytes),
      /verification key/);
    assert.equal(calls.parse, 0);
  }
});
