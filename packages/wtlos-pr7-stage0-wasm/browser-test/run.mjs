// Isolated Chromium key-parser fixture. It does not construct or submit a proof.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';

const EXPECTED_KEY_SHA256 = '44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1';
const EXPECTED_KEY_BYTES = 72_498_469;
const EXPECTED_SOURCE_TREE = '7a22196e1d4a791b452a6140bdfa915298f3f1da';
const [pkgArg, keyArg, resultArg] = process.argv.slice(2);
if (!keyArg || !existsSync(keyArg)) {
  throw new Error('HOLD: exact converted Stage 0 test key is missing');
}
if (!pkgArg || !resultArg) {
  throw new Error('usage: run.mjs PKG_DIR CONVERTED_KEY_PATH RESULT_JSON');
}
const pkg = path.resolve(pkgArg);
const key = path.resolve(keyArg);
if (statSync(key).size !== EXPECTED_KEY_BYTES) {
  throw new Error('HOLD: converted Stage 0 key byte length mismatch');
}
const keyHash = createHash('sha256');
for await (const chunk of createReadStream(key)) keyHash.update(chunk);
assert.equal(keyHash.digest('hex'), EXPECTED_KEY_SHA256, 'converted Stage 0 key SHA-256');
const { chromium } = await import('playwright');
for (const name of ['stage0.js', 'stage0_bg.wasm']) {
  assert.ok(existsSync(path.join(pkg, name)), `missing generated ${name}`);
}

const served = new Map([
  ['/stage0.js', [path.join(pkg, 'stage0.js'), 'text/javascript']],
  ['/stage0_bg.wasm', [path.join(pkg, 'stage0_bg.wasm'), 'application/wasm']],
  ['/converted-key.bin', [key, 'application/octet-stream']],
]);
const server = createServer((request, response) => {
  if (request.url === '/') {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end('<!doctype html><title>UNSAFE_STAGE0_NO_GO</title>');
    return;
  }
  const route = served.get(request.url);
  if (!route) {
    response.writeHead(404);
    response.end();
    return;
  }
  const [file, type] = route;
  response.writeHead(200, {
    'Content-Type': type,
    'Content-Length': statSync(file).size,
    'Cache-Control': 'no-store',
  });
  createReadStream(file).pipe(response);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    return url.origin === origin ? route.continue() : route.abort();
  });
  await page.goto(origin, { waitUntil: 'load' });
  const observed = await page.evaluate(async ({ expectedHash, expectedTree }) => {
    const { default: init, UnsafeStage0Params } = await import('/stage0.js');
    await init(new URL('/stage0_bg.wasm', location.href));
    const reject = (run) => {
      try {
        run();
        return false;
      } catch {
        return true;
      }
    };
    const sourceTree = UnsafeStage0Params.sourceTree();
    const parameterSha256 = UnsafeStage0Params.parameterSha256();
    const emptyRejected = reject(() => UnsafeStage0Params.fromBinary(new Uint8Array()));
    const keyResponse = await fetch('/converted-key.bin', { cache: 'no-store' });
    if (!keyResponse.ok) throw new Error('local key fixture unavailable');
    const keyBytes = new Uint8Array(await keyResponse.arrayBuffer());
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', keyBytes));
    const actualHash = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
    const exactHash = actualHash === expectedHash;
    keyBytes[0] ^= 1;
    const changedRejected = reject(() => UnsafeStage0Params.fromBinary(keyBytes));
    keyBytes[0] ^= 1;
    const params = UnsafeStage0Params.fromBinary(keyBytes);
    const unsupportedKindRejected = reject(() => params.unsafeStage0Tx('unsupported', {}));
    params.free();
    return {
      source_tree: sourceTree,
      parameter_sha256: parameterSha256,
      exact_key_sha256_checked_in_browser: exactHash,
      exact_key_parsed_in_browser: true,
      empty_key_rejected_in_browser: emptyRejected,
      changed_byte_rejected_in_browser: changedRejected,
      unsupported_kind_rejected_in_browser: unsupportedKindRejected,
      source_tree_matched_in_browser: sourceTree === expectedTree,
    };
  }, { expectedHash: EXPECTED_KEY_SHA256, expectedTree: EXPECTED_SOURCE_TREE });
  for (const field of [
    'exact_key_sha256_checked_in_browser',
    'exact_key_parsed_in_browser',
    'empty_key_rejected_in_browser',
    'changed_byte_rejected_in_browser',
    'unsupported_kind_rejected_in_browser',
    'source_tree_matched_in_browser',
  ]) assert.equal(observed[field], true, `browser fixture ${field}`);
  assert.equal(observed.source_tree, EXPECTED_SOURCE_TREE);
  assert.equal(observed.parameter_sha256, EXPECTED_KEY_SHA256);
  writeFileSync(path.resolve(resultArg), JSON.stringify({
    schema: 'telos-pr7-unsafe-stage0-browser-key-test-v1',
    status: 'UNSAFE_STAGE0_NO_GO',
    ...observed,
    browser_proof_tested: false,
  }, null, 2) + '\n');
  console.log('PASS: Chromium parsed exact Stage 0 key and rejected empty/changed bytes; browser proof remains untested');
} finally {
  if (browser) await browser.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
