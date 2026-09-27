const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const ts = require('typescript');

// Execute the actual source methods with inert providers. This checks that a
// profile cannot send a private witness to a delegated or legacy prover.
function sourceMethod(filename, owner, name) {
  const file = path.join(__dirname, '../src', filename);
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  let members;
  if (owner === 'class') {
    const klass = ast.statements.find(node =>
      ts.isClassDeclaration(node) && node.name?.text === 'ZkBobClient');
    assert.ok(klass, 'ZkBobClient source class missing');
    members = klass.members;
  } else {
    const declaration = ast.statements.filter(ts.isVariableStatement)
      .flatMap(node => node.declarationList.declarations)
      .find(node => node.name.getText(ast) === 'obj');
    assert.ok(declaration && ts.isObjectLiteralExpression(declaration.initializer),
      'worker RPC object missing');
    members = declaration.initializer.properties;
  }
  const matches = members.filter(node => ts.isMethodDeclaration(node) &&
    node.name.getText(ast) === name);
  assert.equal(matches.length, 1, `${filename}: expected one ${name} method`);
  return matches[0].getText(ast);
}

function sourceFunction(filename, name) {
  const file = path.join(__dirname, '../src', filename);
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const matches = ast.statements.filter(node => ts.isFunctionDeclaration(node) &&
    node.name?.text === name);
  assert.equal(matches.length, 1, `${filename}: expected one ${name} function`);
  return matches[0].getText(ast);
}

function compileHarness(source, wrapper, bindings) {
  const result = ts.transpileModule(wrapper(source), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    reportDiagnostics: true,
  });
  assert.deepEqual(result.diagnostics, []);
  const exports = {};
  vm.runInNewContext(result.outputText, { exports, ...bindings }, { timeout: 2000 });
  return exports.harness;
}

test('WTLOS profile rejects every client prover mode before a private witness leaves', async () => {
  const calls = { delegated: 0, worker: 0, hardware: 0, verify: 0 };
  const modes = { Local: 'Local', Delegated: 'Delegated',
    DelegatedWithFallback: 'DelegatedWithFallback' };
  const Harness = compileHarness(
    sourceMethod('client.ts', 'class', 'proveTx'),
    method => `export class harness { ${method} }`,
    { InternalError: Error, ProverMode: modes, TxProofError: Error,
      isDesktop: () => { calls.hardware++; return false; },
      proveTxNativeHardware: async () => { calls.hardware++; },
      console: { debug() {}, error() {}, warn() {} } },
  );
  const privateWitness = { secret: 'synthetic-only' };
  for (const [mode, forced] of [
    [modes.Local, undefined], [modes.Delegated, undefined],
    [modes.DelegatedWithFallback, undefined], [modes.Local, modes.Delegated],
  ]) {
    const context = {
      pool: () => ({ wtlosReleaseProfile: { circuitSourceTree: '7a22196e' } }),
      getProverMode: () => mode,
      prover: () => ({ proveTx: async () => { calls.delegated++; return {}; } }),
      worker: {
        proveTx: async () => { calls.worker++; return {}; },
        verifyTxProof: async () => { calls.verify++; return true; },
      },
      snarkParamsAlias: () => 'WTLOS',
    };
    await assert.rejects(
      Harness.prototype.proveTx.call(context, { root: 'synthetic' }, privateWitness, forced),
      /WTLOS PR7 proving is not wired/,
    );
  }
  assert.deepEqual(calls, { delegated: 0, worker: 0, hardware: 0, verify: 0 });

  // The guard must not disable an unrelated legacy pool.
  const legacy = {
    pool: () => ({}), getProverMode: () => modes.Delegated,
    prover: () => ({ proveTx: async () => { calls.delegated++; return 'proof'; } }),
    worker: { verifyTxProof: async () => { calls.verify++; return true; } },
    snarkParamsAlias: () => 'legacy',
  };
  const result = await Harness.prototype.proveTx.call(legacy, { root: 'r' }, privateWitness);
  assert.equal(result.proof, 'proof');
  assert.equal(calls.delegated, 1);
  assert.equal(calls.verify, 1);
});

test('PR7 source-tagged params require a matching release profile before worker creation', () => {
  const helperName = 'assertWTLOSParamProfileBinding';
  const workerInit = sourceMethod('client.ts', 'class', 'workerInit');
  assert.ok(workerInit.indexOf(`${helperName}(config.pools, allParamsSet)`) > 0);
  assert.ok(workerInit.indexOf(`${helperName}(config.pools, allParamsSet)`) <
    workerInit.indexOf('new Worker('));
  const validate = compileHarness(
    sourceFunction('client.ts', helperName),
    declaration => `export const harness = ${declaration};`,
    { GLOBAL_PARAMS_NAME: '__globalParams', InternalError: Error },
  );
  const tree = '7a22196e1d4a791b452a6140bdfa915298f3f1da';
  const params = { wtlosCircuitSourceTree: tree,
    transferParamsSha256: 'a'.repeat(64), transferVkSha256: 'b'.repeat(64) };
  const release = { circuitSourceTree: tree,
    transferParamsSha256: params.transferParamsSha256,
    transferVkSha256: params.transferVkSha256 };
  assert.throws(() => validate({ WTLOS: {
    delegatedProverUrls: ['https://example.invalid'],
  } }, { __globalParams: params }), /PR7 parameters without a WTLOS-only release profile/);
  assert.throws(() => validate({ WTLOS: { wtlosReleaseProfile: release },
    legacy: {} }, { __globalParams: params }), /PR7 parameters without a WTLOS-only release profile/);
  assert.doesNotThrow(() => validate({ WTLOS: { wtlosReleaseProfile: release } },
    { __globalParams: params }));
  assert.throws(() => validate({ WTLOS: { wtlosReleaseProfile: release } },
    { __globalParams: { ...params, transferVkSha256: 'c'.repeat(64) } }),
  /SNARK artifacts do not match/);
  assert.doesNotThrow(() => validate({ legacy: {} }, { __globalParams: {} }));
});

test('direct worker RPC rejects PR7 before legacy params or Proof.tx', async () => {
  const calls = { params: 0, proof: 0 };
  const txParams = {
    WTLOS: { wtlosCircuitSourceTree: () => '7a22196e',
      getParams: async () => { calls.params++; return 'params'; } },
    legacy: { wtlosCircuitSourceTree: () => undefined,
      getParams: async () => { calls.params++; return 'params'; } },
  };
  const wasm = { Proof: { tx: () => { calls.proof++; return 'legacy proof'; } } };
  const worker = compileHarness(
    sourceMethod('worker.ts', 'object', 'proveTx'),
    method => `export const harness = { ${method} };`,
    { txParams, wasm, InternalError: Error, console: { debug() {} } },
  );
  await assert.rejects(worker.proveTx('WTLOS', {}, { secret: 'synthetic-only' }),
    /WTLOS PR7 proving is not wired/);
  assert.deepEqual(calls, { params: 0, proof: 0 });
  assert.equal(await worker.proveTx('legacy', {}, {}), 'legacy proof');
  assert.deepEqual(calls, { params: 1, proof: 1 });
});
