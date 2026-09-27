// Offline-only synthetic witness proof, using unqualified Stage 0 material.
// UNSAFE_STAGE0_NO_GO: never point this at a wallet, relayer, RPC or chain.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';

const KEY_SHA256 = '44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1';
const KEY_BYTES = 72_498_469;
const SOURCE_TREE = '7a22196e1d4a791b452a6140bdfa915298f3f1da';
const WASM_SHA256 = 'acfdab00329bea7f829320df559baebf63c1320b04ee8173b959b51e404c9021';
const JS_SHA256 = 'daeb487356dcc1168776cbc9e23230f43fd3fa9a143411f5e786d99e39789df8';
const [pkgArg, keyArg, witnessArg, resultArg] = process.argv.slice(2);
if (![pkgArg, keyArg, witnessArg, resultArg].every(Boolean)) {
  throw new Error('usage: prove-stage0.mjs PKG_DIR STAGE0_CONVERTED_KEY SYNTHETIC_WITNESS_TUPLE RESULT_JSON');
}
const [pkg, key, witnessFile, resultFile] = [pkgArg, keyArg, witnessArg, resultArg].map((part) => path.resolve(part));
for (const file of [key, witnessFile, path.join(pkg, 'stage0.js'), path.join(pkg, 'stage0_bg.wasm')]) {
  assert.ok(existsSync(file), `missing test-only input: ${file}`);
}
async function hashFile(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
assert.equal(statSync(key).size, KEY_BYTES);
assert.equal(await hashFile(key), KEY_SHA256);
assert.equal(await hashFile(path.join(pkg, 'stage0.js')), JS_SHA256);
assert.equal(await hashFile(path.join(pkg, 'stage0_bg.wasm')), WASM_SHA256);
const witnessSha256 = await hashFile(witnessFile);
const tuple = JSON.parse(readFileSync(witnessFile, 'utf8'));
assert.equal(tuple.length, 2);
assert.equal(tuple[0].memo?.length > 0, true);
const { chromium } = await import('playwright');

const served = new Map([
  ['/stage0.js', [path.join(pkg, 'stage0.js'), 'text/javascript']],
  ['/stage0_bg.wasm', [path.join(pkg, 'stage0_bg.wasm'), 'application/wasm']],
  ['/converted-key.bin', [key, 'application/octet-stream']],
]);
const server = createServer((request, response) => {
  if (request.url === '/') {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end('<!doctype html><title>UNSAFE_STAGE0_NO_GO browser proof fixture</title>');
    return;
  }
  const route = served.get(request.url);
  if (!route) {
    response.writeHead(404);
    response.end();
    return;
  }
  const [file, type] = route;
  response.writeHead(200, { 'Content-Type': type, 'Content-Length': statSync(file).size, 'Cache-Control': 'no-store' });
  createReadStream(file).pipe(response);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({
    headless: true,
    executablePath: process.env.UNSAFE_STAGE0_TEST_CHROMIUM_BIN,
  });
  const page = await browser.newPage();
  page.on('console', (line) => console.log(`browser: ${line.text()}`));
  page.on('pageerror', (error) => console.error(`browser-error: ${error.message}`));
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    return url.origin === origin ? route.continue() : route.abort();
  });
  await page.goto(origin, { waitUntil: 'load' });
  console.log('UNSAFE_STAGE0_NO_GO: exact hosted JS/WASM and synthetic witness pinned; starting offline browser proof');
  const started = Date.now();
  const observed = await page.evaluate(async ({ witness, expectedTree, expectedKey }) => {
    const { default: init, UnsafeStage0Params } = await import('/stage0.js');
    await init(new URL('/stage0_bg.wasm', location.href));
    if (UnsafeStage0Params.sourceTree() !== expectedTree) throw new Error('wrong source tree');
    if (UnsafeStage0Params.parameterSha256() !== expectedKey) throw new Error('wrong Stage 0 key identity');
    const response = await fetch('/converted-key.bin', { cache: 'no-store' });
    if (!response.ok) throw new Error('local key fetch failed');
    const keyBytes = new Uint8Array(await response.arrayBuffer());
    const params = UnsafeStage0Params.fromBinary(keyBytes);
    let completed = false;
    try {
      const proxy = new Array(20).fill(0);
      proxy[18] = 0xf0;
      proxy[19] = 0x03;
      const deposit = {
        public: witness[0], secret: witness[1], signing_key: '42',
        pool_id: 40003, amount: '1000000000', fee: '0', proxy,
      };
      const proof = params.unsafeStage0Tx('deposit', deposit);
      completed = true;
      return {
        source_tree: proof.source_tree,
        converted_params_sha256: proof.converted_params_sha256,
        stage0_mpc_sha256: proof.stage0_mpc_sha256,
        unsafe_stage0_only: proof.unsafe_stage0_only,
        public: proof.public,
        memo: Array.from(proof.memo),
        inputs: proof.inputs,
        proof: proof.proof,
      };
    } finally { if (completed) params.free(); }
  }, { witness: tuple, expectedTree: SOURCE_TREE, expectedKey: KEY_SHA256 });
  assert.equal(observed.source_tree, SOURCE_TREE);
  assert.equal(observed.converted_params_sha256, KEY_SHA256);
  assert.equal(observed.unsafe_stage0_only, true);
  assert.equal(observed.inputs.length, 5);
  assert.deepEqual(Object.keys(observed.proof).sort(), ['a', 'b', 'c']);
  writeFileSync(resultFile, JSON.stringify({
    schema: 'telos-pr7-unsafe-stage0-browser-deposit-proof-v1',
    status: 'UNSAFE_STAGE0_NO_GO',
    source_head: '52fa9d79f69d15d3f837516596347cbce1d51365',
    source_tree: SOURCE_TREE,
    js_sha256: JS_SHA256,
    wasm_sha256: WASM_SHA256,
    key_sha256: KEY_SHA256,
    witness_sha256: witnessSha256,
    browser_elapsed_ms: Date.now() - started,
    result: observed,
    verified_against_vk: false,
  }, null, 2) + '\n');
  console.log(`PASS: isolated Chromium constructed unqualified Stage 0 deposit proof in ${Date.now() - started} ms; VK verification pending`);
} finally {
  if (browser) await browser.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
