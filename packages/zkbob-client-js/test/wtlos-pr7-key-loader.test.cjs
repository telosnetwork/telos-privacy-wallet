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

const tree = '7a22196e1d4a791b452a6140bdfa915298f3f1da';
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
function moduleFor(hash = sha(key), source = tree) {
  const calls = {parse: 0};
  return {
    calls,
    module: {WTLOSPR7Params: {
      sourceTree: () => source,
      parameterSha256: () => hash,
      fromBinary: bytes => { calls.parse++; return {byteLength: bytes.length}; },
    }},
  };
}

test('matching PR7 source, key, and VK bytes reach only the distinct PR7 parser', async () => {
  const params = new SnarkParams(config());
  const {calls, module} = moduleFor();
  const loaded = await params.loadWTLOSPR7ArtifactsFromBytes(module, key, vk);
  assert.equal(calls.parse, 1);
  assert.equal(loaded.params.byteLength, key.length);
  assert.deepEqual(Object.keys(loaded.verificationKey).sort(),
    ['alpha', 'beta', 'delta', 'gamma', 'ic']);
  await assert.rejects(params.getParams({Params: {fromBinary: () => {
    throw new Error('legacy parser reached');
  }}}), /source-bound browser loader/);
});

test('PR7 loader rejects source, module key claim, and byte mismatches before parsing', async () => {
  const params = new SnarkParams(config());
  for (const {module, calls} of [
    moduleFor(sha(key), '0'.repeat(40)),
    moduleFor('f'.repeat(64)),
    {module: {UnsafeStage0Params: moduleFor().module.WTLOSPR7Params}, calls: {parse: 0}},
  ]) {
    await assert.rejects(params.loadWTLOSPR7ArtifactsFromBytes(module, key, vk));
    assert.equal(calls.parse, 0);
  }
  const {module, calls} = moduleFor();
  await assert.rejects(params.loadWTLOSPR7ArtifactsFromBytes(module,
    Uint8Array.from([1, 2, 3, 5]), vk), /byte hash mismatch/);
  await assert.rejects(params.loadWTLOSPR7ArtifactsFromBytes(module,
    key, Uint8Array.from([0])), /byte hash mismatch/);
  assert.equal(calls.parse, 0);
});

test('PR7 loader requires complete pins and valid VK JSON before parsing', async () => {
  const partial = new SnarkParams({...config(), transferVkSha256: undefined});
  const {module} = moduleFor();
  await assert.rejects(partial.loadWTLOSPR7ArtifactsFromBytes(module, key, vk),
    /source, params, and VK hashes are required/);

  for (const bytes of [new TextEncoder().encode('not-json'),
    new TextEncoder().encode('{}')]) {
    const params = new SnarkParams(config(key, bytes));
    const {module: matching, calls} = moduleFor();
    await assert.rejects(params.loadWTLOSPR7ArtifactsFromBytes(matching, key, bytes),
      /verification key/);
    assert.equal(calls.parse, 0);
  }
});
