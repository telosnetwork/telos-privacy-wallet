// Isolated privacy regressions. Runs application code with mocked UI/native boundaries.
// After installing the wallet's dependencies: node --test scripts/privacy-hardening.test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');
const babel = require('@babel/core');
const jsx = require('@babel/preset-react');
const commonjs = require('@babel/plugin-transform-modules-commonjs');

const root = path.resolve(__dirname, '..');
const app = 'apps/zktelos-wallet/';
const baseline = process.env.PRIVACY_TEST_REF;
const quiet = { log() {}, warn() {}, error() {}, debug() {}, info() {} };
const mode = { Local: 'local', DelegatedWithFallback: 'remote-fallback' };
const source = file => baseline
  ? execFileSync('git', ['show', `${baseline}:${file}`], { cwd: root, encoding: 'utf8' })
  : fs.readFileSync(path.join(root, file), 'utf8');

function runModule(file, mocks = {}, globals = {}) {
  const result = babel.transformSync(source(file), {
    filename: file, configFile: false, babelrc: false,
    presets: [[jsx, { runtime: 'automatic' }]], plugins: [commonjs],
  });
  const module = { exports: {} };
  const sandbox = {
    module, exports: module.exports, console: quiet,
    process: { env: {} }, URL, URLSearchParams, TextEncoder,
    require(name) {
      if (Object.prototype.hasOwnProperty.call(mocks, name)) return mocks[name];
      if (name === 'react/jsx-runtime') return { jsx: (type, props) => ({ type, props }), jsxs: (type, props) => ({ type, props }) };
      throw new Error(`Unexpected dependency: ${name}`);
    },
    ...globals,
  };
  vm.runInNewContext(result.code, sandbox, { filename: file });
  return module.exports;
}

function callback(file, name, globals) {
  let found;
  const ast = babel.parseSync(source(file), {
    filename: file, configFile: false, babelrc: false, parserOpts: { plugins: ['jsx'] },
  });
  babel.traverse(ast, {
    FunctionDeclaration(p) { if (p.node.id?.name === name) found = p.node; },
    VariableDeclarator(p) {
      if (p.node.id.name === name && p.node.init?.type === 'CallExpression') found = p.node.init.arguments[0];
    },
  });
  assert.ok(found, `Cannot find application callback ${name}`);
  const expression = found.type === 'FunctionDeclaration'
    ? { ...found, type: 'FunctionExpression' } : found;
  const code = babel.transformFromAstSync(babel.types.file(babel.types.program([
    babel.types.expressionStatement(expression),
  ])), undefined, { configFile: false, babelrc: false }).code;
  return vm.runInNewContext(code, { console: quiet, ...globals });
}

function clientAdapter(captured) {
  return runModule(app + 'src/contexts/ZkAccountContext/zp.js', {
    ethers: { ethers: { utils: { isValidMnemonic: () => false, arrayify: x => x } } },
    'zkbob-client-js': { ZkBobClient: { create: (...args) => { captured.push(args); return Promise.resolve({}); } } },
    'zkbob-client-js/lib/utils': { deriveSpendingKeyZkBob: x => x },
    'zkbob-client-js/lib/config': { ProverMode: mode },
    constants: { TX_STATUSES: {} },
    config: { pools: { test: { delegatedProverUrls: ['https://example.invalid'] } }, chains: {}, snarkParamsSet: {} },
  }).default;
}

test('mounting support context performs no IP lookup or telemetry tagging', async () => {
  const calls = [];
  const effects = [];
  const component = runModule(app + 'src/contexts/SupportIdContext/index.js', {
    react: { createContext: () => ({ Provider: 'provider' }), useState: () => [null, () => {}], useCallback: f => f, useEffect: f => effects.push(f) },
    uuid: { v4: () => 'local-support-id' },
    '@sentry/react': { configureScope: f => f({ setTag: (...args) => calls.push(args) }) },
  }, { fetch: async url => { calls.push(url); return { json: async () => ({ ip: '192.0.2.1' }) }; } });
  component.SupportIdContextProvider({ children: null });
  effects.forEach(f => f());
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, []);
});

test('route initialization does not start telemetry even with build credentials', () => {
  const file = app + 'src/pages/index.js';
  const imports = {};
  const ast = babel.parseSync(source(file), { configFile: false, babelrc: false, parserOpts: { plugins: ['jsx'] } });
  ast.program.body.filter(n => n.type === 'ImportDeclaration').forEach(n => { imports[n.source.value] = {}; });
  const calls = [];
  imports.history = { createBrowserHistory: () => ({}) };
  imports['@sentry/react'] = { init: (...args) => calls.push(args), withSentryRouting: x => x,
    reactRouterV5Instrumentation() {}, Integrations: { Breadcrumbs: function () {} } };
  imports['@sentry/tracing'] = { BrowserTracing: function () {} };
  runModule(file, imports, { process: { env: {
    REACT_APP_SENTRY_PUBLIC_KEY: 'test', REACT_APP_SENTRY_PRIVATE_KEY: 'test', REACT_APP_SENTRY_PROJECT_ID: '1',
  } } });
  assert.deepEqual(calls, []);
});

test('client initialization does not transmit the local support identifier', async () => {
  const calls = [];
  const zp = clientAdapter(calls);
  const progress = () => {};
  const create = callback(app + 'src/contexts/ZkAccountContext/index.js', 'createClients', {
    poolAliases: ['test'], zkClients: {}, zp, supportId: 'correlation-sentinel',
    updateLoadingPercentage: progress, setZkClients() {},
    Sentry: { captureException(error) { throw error; } },
  });
  await create();
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0].supportId, undefined);
  assert.equal(calls[0][2], progress);
});

test('account login keeps witnesses local even when a remote mode is requested', async () => {
  const zp = clientAdapter([]);
  let login;
  await zp.createAccount({ currentPool: () => 'test', login: async args => { login = args; } }, 'dummy-key', 0, true);
  assert.equal(login.proverMode, mode.Local);
});

test('gift redemption keeps witnesses local even when a prover URL exists', async () => {
  let selectedMode;
  const redeem = callback(app + 'src/contexts/ZkAccountContext/index.js', 'redeemGiftCard', {
    currentPool: { alias: 'test' }, giftCard: { poolAlias: 'test' },
    config: { pools: { test: { delegatedProverUrls: ['https://example.invalid'] } } }, ProverMode: mode,
    zkClient: { redeemGiftCard: async (_gift, m) => { selectedMode = m; return 'job'; }, waitJobTxHash: async () => 'tx' },
    switchToPool: async () => {}, setGiftCardTxHash() {}, deleteGiftCard() {}, updatePoolData() {},
    Sentry: { captureException(error) { throw error; } },
  });
  await redeem();
  assert.equal(selectedMode, mode.Local);
});

for (const environment of ['prod', 'dev']) {
  test(`${environment} pool configuration contains no remote prover endpoints`, () => {
    const config = runModule(app + 'src/config/index.js', {}, { process: { env: { REACT_APP_CONFIG: environment } } }).default;
    for (const pool of Object.values(config.pools)) assert.equal(pool.delegatedProverUrls.length, 0);
  });
}

function electronHarness(failProof = false) {
  const events = new Map();
  const handlers = new Map();
  const logs = [];
  const reads = [];
  const proofs = [];
  const sandbox = {
    __dirname: '/mock/electron', process: { platform: 'linux' }, URL,
    console: Object.fromEntries(['log', 'warn', 'error'].map(key => [key, (...args) => logs.push(args)])),
    require(name) {
      if (name === 'electron') return {
        app: { isPackaged: true, commandLine: { appendSwitch() {} }, whenReady: () => ({ then() {} }), on: (name, fn) => events.set(name, fn) },
        protocol: { registerSchemesAsPrivileged() {} }, ipcMain: { handle: (name, fn) => handlers.set(name, fn) },
      };
      if (name === 'path') return path;
      if (name === 'fs') return { readFileSync: filename => { reads.push(filename); return filename; } };
      if (name === 'libzkbob-rs-node') return { readParamsFromBinary: bin => bin, proveTxAsync: async params => {
        proofs.push(params);
        if (failProof) throw new Error('private-witness-sentinel');
        return { proof: 'synthetic-proof' };
      } };
      throw new Error(`Unexpected dependency: ${name}`);
    },
  };
  vm.runInNewContext(source(app + 'electron/main.js') + '\nsetupRustIpcHandler();', sandbox);
  return { events, handlers, logs, reads, proofs };
}

test('packaged desktop rejects invalid server certificates', () => {
  const { events } = electronHarness();
  let trusted;
  let prevented = false;
  events.get('certificate-error')({ preventDefault() { prevented = true; } }, null,
    'https://example.invalid', 'ERR_CERT_AUTHORITY_INVALID', {}, value => { trusted = value; });
  assert.equal(trusted, false);
  assert.equal(prevented, false);
});

test('native proving does not log private input data', async () => {
  const { handlers, logs } = electronHarness();
  const result = await handlers.get('prove-tx')(null, [{ nullifier: 'public' }, { witness: 'private-witness-sentinel' }, 'prod']);
  assert.equal(result.proof, 'synthetic-proof');
  assert.equal(JSON.stringify(logs).includes('private-witness-sentinel'), false);
});

test('native proving errors do not expose private data to logs or renderer', async () => {
  const { handlers, logs } = electronHarness(true);
  const result = await handlers.get('prove-tx')(null, [{}, { witness: 'private-witness-sentinel' }, 'prod']);
  assert.equal(result.success, false);
  assert.equal(JSON.stringify([logs, result]).includes('private-witness-sentinel'), false);
});

test('native proving selects and caches the requested bundled parameter set', async () => {
  const { handlers, reads, proofs } = electronHarness();
  for (const alias of ['prod', 'staging', 'prod']) {
    await handlers.get('prove-tx')(null, [{}, {}, alias]);
  }
  assert.deepEqual(reads, ['/mock/electron/assets/transfer_params_prod.bin', '/mock/electron/assets/transfer_params.bin']);
  assert.deepEqual(proofs, [reads[0], reads[1], reads[0]]);
});

test('native proving fails closed for missing, unknown, or path-like parameter aliases', async () => {
  const { handlers, reads, proofs } = electronHarness();
  for (const alias of [undefined, 'unknown', '__proto__', '../transfer_params_prod.bin']) {
    const result = await handlers.get('prove-tx')(null, [{}, {}, alias]);
    assert.equal(result.success, false);
  }
  assert.deepEqual(reads, []);
  assert.deepEqual(proofs, []);
});
