// Offline-only synthetic witness proof, using unqualified Stage 0 material.
// UNSAFE_STAGE0_NO_GO: never point this at a wallet, relayer, RPC or chain.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const KEY_SHA256 = '44f01686622e4935d67a481a0668837afa5c6a8c54b1b9de03280744284d50c1';
const KEY_BYTES = 72_498_469;
const SOURCE_TREE = '7a22196e1d4a791b452a6140bdfa915298f3f1da';
const MPC_SHA256 = 'd00b7238ab8787cb0d321e6bc910ea8cf1ec02bbf68e7a57555c11ff7843ba30';
const WITNESS_SHA256 = 'dd1126699b58d829f3735d6085f406ae613402e7758ffa524cf68b6a6bdaa015';
const WITNESS_SOURCE_SHA256 = 'dab7b2c589a5cf161cda9e3f23997c748831576b88df657facc3b452262459e5';
const PROOF_TIMEOUT_MS = 600_000;
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const git = (...args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
const [pkgArg, keyArg, witnessArg, archiveArg, archiveSha256, resultArg] = process.argv.slice(2);
if (![pkgArg, keyArg, witnessArg, archiveArg, archiveSha256, resultArg].every(Boolean)) {
  throw new Error('usage: prove-stage0.mjs PKG_DIR STAGE0_CONVERTED_KEY SYNTHETIC_WITNESS_TUPLE HOSTED_ARTIFACT_ZIP INDEPENDENT_GITHUB_ZIP_SHA256 NEW_RESULT_JSON');
}
assert.match(archiveSha256, /^[0-9a-f]{64}$/);
const [pkg, key, witnessFile, archiveFile, resultFile] =
  [pkgArg, keyArg, witnessArg, archiveArg, resultArg].map((part) => path.resolve(part));
for (const file of [key, witnessFile, archiveFile, path.join(pkg, 'stage0.js'), path.join(pkg, 'stage0_bg.wasm')]) {
  assert.ok(existsSync(file), `missing test-only input: ${file}`);
}
assert.ok(!existsSync(resultFile), 'refuse to overwrite existing proof evidence');
async function hashFile(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
const hashBytes = (bytes) => createHash('sha256').update(bytes).digest('hex');
assert.equal(await hashFile(archiveFile), archiveSha256, 'hosted ZIP digest differs from independent GitHub readback');
const archiveEntries = execFileSync('unzip', ['-Z1', archiveFile], { encoding: 'utf8' }).trim().split('\n').sort();
assert.deepEqual(archiveEntries, ['MANIFEST.json', 'SHA256SUMS', 'pkg/stage0.js', 'pkg/stage0_bg.wasm'].sort());
const zipEntry = (name) => execFileSync('unzip', ['-p', archiveFile, name], { maxBuffer: 10_000_000 });
const manifestBytes = zipEntry('MANIFEST.json');
const checksumLines = zipEntry('SHA256SUMS').toString('utf8').trim().split('\n');
const archiveChecksums = new Map(checksumLines.map((line) => {
  const [digest, name] = line.split('  ');
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.ok(name);
  return [name, digest];
}));
assert.deepEqual([...archiveChecksums.keys()].sort(), ['MANIFEST.json', 'pkg/stage0.js', 'pkg/stage0_bg.wasm'].sort());
for (const name of archiveChecksums.keys()) assert.equal(hashBytes(zipEntry(name)), archiveChecksums.get(name), name);
const witnessSha256 = await hashFile(witnessFile);
assert.equal(witnessSha256, WITNESS_SHA256, 'wrong synthetic PR7 deposit witness');
const witnessSource = path.resolve(path.dirname(witnessFile), '../../tool_sources/witness/main.rs');
assert.ok(existsSync(witnessSource), 'sealed synthetic witness source is missing');
assert.equal(await hashFile(witnessSource), WITNESS_SOURCE_SHA256, 'synthetic witness source mismatch');
const witnessCode = readFileSync(witnessSource, 'utf8');
for (const expected of [
  'const POOL_ID: u64 = 40003;',
  'const DEPOSIT: u64 = 1_000_000_000;',
  'let sigma = Num::from(42u64);',
  "proxy[18..].copy_from_slice(&[0xf0, 0x03]);",
  'let delta = make_delta(signed_token_delta, Num::ZERO, Num::from(current_index as u64), pool);',
]) assert.ok(witnessCode.includes(expected), `synthetic witness semantic source mismatch: ${expected}`);
const tuple = JSON.parse(readFileSync(witnessFile, 'utf8'));
assert.equal(tuple.length, 2);
assert.equal(tuple[0].root, '11469701942666298368112882412133877458305516134926649826543144744382391691533');
assert.equal(tuple[0].delta, '1078478746526027043706064604526046285837506688334890520961587721799387648');
assert.equal(tuple[1].eddsa_a, '3565266709075800875210742045194644592419627314571711466554275470461838539738');
assert.equal(tuple[1].tx.input[0].b, '0');
assert.equal(tuple[1].tx.output[0].b, '1000000000');
assert.equal(git('status', '--porcelain=v1', '--untracked-files=all'), '', 'source checkout must be clean');
const sourceHead = git('rev-parse', 'HEAD');
const sourceTree = git('rev-parse', 'HEAD^{tree}');
const manifest = JSON.parse(manifestBytes.toString('utf8'));
assert.equal(manifest.schema, 'telos-pr7-unsafe-stage0-browser-evidence-v1');
assert.equal(manifest.status, 'UNSAFE_STAGE0_NO_GO');
assert.equal(manifest.qualification.browser_wasm_built, true);
for (const gate of ['qualified_ceremony', 'wallet_worker_wired', 'production_release_approved']) {
  assert.equal(manifest.qualification[gate], false, gate);
}
assert.equal(manifest.source.head, sourceHead, 'hosted artifact must match this exact source HEAD');
assert.equal(manifest.source.event_pull_request_head, sourceHead, 'hosted artifact must pin exact PR HEAD');
assert.equal(manifest.source.git_tree, sourceTree, 'hosted artifact must match this exact source tree');
assert.equal(manifest.source.vendored_pr7_git_tree, SOURCE_TREE);
assert.equal(manifest.source.stage0_wasm_git_tree, git('rev-parse', 'HEAD:packages/wtlos-pr7-stage0-wasm'));
assert.equal(manifest.source.proof_git_tree, git('rev-parse', 'HEAD:packages/wtlos-pr7-proof'));
const sourcePin = JSON.parse(readFileSync(path.join(repo, 'packages/wtlos-pr7-stage0-wasm/SOURCE-PIN.json'), 'utf8'));
assert.equal(sourcePin.vendored_pr7_git_tree, SOURCE_TREE);
assert.equal(sourcePin.converted_stage0_browser_key_sha256, KEY_SHA256);
assert.equal(sourcePin.transfer_stage0_mpc_sha256, MPC_SHA256);
assert.equal(sourcePin.phase2_vendored_package_tree, manifest.source.phase2_vendored_package_tree);
assert.equal(sourcePin.phase2_vendored_manifest_sha256, manifest.source.phase2_vendored_manifest_sha256);
assert.equal(manifest.source.converted_stage0_browser_key_sha256, KEY_SHA256);
assert.equal(manifest.source.transfer_stage0_mpc_sha256, MPC_SHA256);
assert.equal(statSync(key).size, KEY_BYTES);
assert.equal(await hashFile(key), KEY_SHA256);
assert.equal(await hashFile(path.join(repo, 'packages/wtlos-pr7-stage0-wasm/SOURCE-PIN.json')), manifest.source.source_pin_sha256);
assert.equal(await hashFile(path.join(repo, 'packages/wtlos-pr7-stage0-wasm/src/lib.rs')), manifest.source.adapter_sha256);
assert.equal(await hashFile(path.join(repo, 'packages/wtlos-pr7-stage0-wasm/Cargo.lock')), manifest.source.cargo_lock_sha256);
assert.equal(await hashFile(path.join(repo, 'packages/wtlos-pr7-proof/Cargo.lock')), manifest.source.proof_cargo_lock_sha256);
const jsSha256 = manifest.files_sha256['pkg/stage0.js'];
const wasmSha256 = manifest.files_sha256['pkg/stage0_bg.wasm'];
assert.match(jsSha256, /^[0-9a-f]{64}$/);
assert.match(wasmSha256, /^[0-9a-f]{64}$/);
assert.equal(await hashFile(path.join(pkg, 'stage0.js')), jsSha256);
assert.equal(await hashFile(path.join(pkg, 'stage0_bg.wasm')), wasmSha256);
assert.equal(hashBytes(zipEntry('pkg/stage0.js')), jsSha256, 'extracted JS differs from hosted ZIP');
assert.equal(hashBytes(zipEntry('pkg/stage0_bg.wasm')), wasmSha256, 'extracted WASM differs from hosted ZIP');
assert.equal(tuple[0].memo?.length > 0, true);
execFileSync('python3', [
  '-I', '-B', path.join(repo, 'packages/wtlos-pr7-stage0-wasm/ci/verify_source.py'), '--key', key,
], { cwd: repo, encoding: 'utf8' });
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
  let proofTimer;
  const proofCall = page.evaluate(async ({ witness, expectedTree, expectedKey }) => {
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
  const timeout = new Promise((_, reject) => {
    proofTimer = setTimeout(() => reject(new Error(`offline browser proof exceeded ${PROOF_TIMEOUT_MS} ms`)), PROOF_TIMEOUT_MS);
  });
  const observed = await Promise.race([proofCall, timeout]).finally(() => clearTimeout(proofTimer));
  assert.equal(observed.source_tree, SOURCE_TREE);
  assert.equal(observed.converted_params_sha256, KEY_SHA256);
  assert.equal(observed.stage0_mpc_sha256, MPC_SHA256);
  assert.equal(observed.unsafe_stage0_only, true);
  assert.equal(observed.inputs.length, 5);
  assert.deepEqual(Object.keys(observed.proof).sort(), ['a', 'b', 'c']);
  writeFileSync(resultFile, JSON.stringify({
    schema: 'telos-pr7-unsafe-stage0-browser-deposit-proof-v1',
    status: 'UNSAFE_STAGE0_NO_GO',
    source_head: sourceHead,
    source_git_tree: sourceTree,
    source_tree: SOURCE_TREE,
    hosted_artifact_zip_sha256: archiveSha256,
    hosted_manifest_sha256: hashBytes(manifestBytes),
    js_sha256: jsSha256,
    wasm_sha256: wasmSha256,
    key_sha256: KEY_SHA256,
    witness_sha256: witnessSha256,
    witness_source_sha256: WITNESS_SOURCE_SHA256,
    synthetic_signer: '42',
    synthetic_pool_id: 40003,
    synthetic_proxy: '0x000000000000000000000000000000000000F003',
    synthetic_amount: '1000000000',
    synthetic_fee: '0',
    proof_timeout_ms: PROOF_TIMEOUT_MS,
    browser_elapsed_ms: Date.now() - started,
    result: observed,
    verified_against_vk: false,
  }, null, 2) + '\n', { flag: 'wx' });
  console.log(`PASS: isolated Chromium constructed unqualified Stage 0 deposit proof in ${Date.now() - started} ms; VK verification pending`);
} finally {
  if (browser) await browser.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
