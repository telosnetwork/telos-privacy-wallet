const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const test = require('node:test');
const ts = require('typescript');

// Exercise the source in isolation without building the WASM or browser app.
require.extensions['.ts'] = (module, filename) => {
  const compiled = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
      esModuleInterop: true }, fileName: filename, reportDiagnostics: true,
  });
  assert.deepEqual(compiled.diagnostics, []);
  module._compile(compiled.outputText, filename);
};
const wallet = require('../src/wtlos-release-profile.ts');
const fixture = require('./fixtures/relayer-v2-profile.json');
const profile = fixture.profile;
const clone = () => structuredClone(profile);
const invalid = value => assert.throws(() => wallet.canonicalWTLOSReleaseProfile(value));
const mismatch = value => assert.throws(() => wallet.assertWTLOSReleaseProfileMatches(value, profile));

test('wallet serialization and SHA-256 match the exact relayer v2 builder fixture', () => {
  assert.equal(fixture.producerModule, 'zp-relayer/pool/WTLOSOnlyReleaseProfile.ts');
  assert.match(fixture.producerCommit, /^[0-9a-f]{40}$/);
  assert.match(fixture.producerTree, /^[0-9a-f]{40}$/);
  assert.match(fixture.producerModuleSha256, /^[0-9a-f]{64}$/);
  assert.equal(wallet.WTLOS_ONLY_RELEASE_SCHEMA, 'telos-wtlos-only-release-v2');
  const canonical = wallet.canonicalWTLOSReleaseProfile(profile);
  assert.deepEqual(canonical, profile);
  assert.equal(JSON.stringify(canonical), JSON.stringify(profile));
  assert.equal(wallet.wtlosReleaseProfileDigest(profile), fixture.digest);
  assert.equal(crypto.createHash('sha256').update(JSON.stringify(profile)).digest('hex'), fixture.digest);
  assert.equal(wallet.assertWTLOSReleaseProfileMatches(profile, profile), fixture.digest);
  const reordered = Object.fromEntries(Object.entries(profile).reverse());
  assert.notEqual(crypto.createHash('sha256').update(JSON.stringify(reordered)).digest('hex'),
    fixture.digest);
  assert.equal(wallet.wtlosReleaseProfileDigest(reordered), fixture.digest);
  const upperCaseRuntime = { ...profile,
    transferVerifierCodeHash: `0x${'C'.repeat(64)}`,
    treeVerifierCodeHash: `0x${'D'.repeat(64)}` };
  assert.equal(wallet.wtlosReleaseProfileDigest(upperCaseRuntime), fixture.digest);
});

test('missing, malformed, unexpected and stale v1 pins reject', () => {
  for (const field of ['transferVerifier', 'transferVerifierCodeHash', 'treeVerifier',
    'treeVerifierCodeHash', 'ceremonyManifestSha256', 'transferVkSha256']) {
    const missing = clone(); delete missing[field]; invalid(missing);
    const malformed = clone(); malformed[field] = '0x'; invalid(malformed);
  }
  invalid({ ...profile, extra: 'unreviewed field' });
  invalid({ ...profile, schema: 'telos-wtlos-only-release-v1' });
  invalid({ ...profile, chainId: 41 });
  invalid({ ...profile, tokenAddress: profile.poolAddress });
  invalid({ ...profile, poolId: '040003' });
});

test('aliased verifier roles and identical verifier runtime hashes reject', () => {
  for (const field of ['transferVerifier', 'treeVerifier']) {
    for (const address of [profile.poolAddress, profile.implementationAddress,
      profile[field === 'transferVerifier' ? 'treeVerifier' : 'transferVerifier'],
      `0x${'0'.repeat(40)}`]) {
      invalid({ ...profile, [field]: address });
    }
  }
  invalid({ ...profile, transferVerifierCodeHash: profile.treeVerifierCodeHash });
});

test('a wrong verifier runtime, role address or digest rejects before send', () => {
  for (const field of ['transferVerifier', 'transferVerifierCodeHash',
    'treeVerifier', 'treeVerifierCodeHash', 'implementationCodeHash']) {
    const changed = clone();
    changed[field] = field.endsWith('CodeHash') ? `0x${'9'.repeat(64)}` : `0x${'9'.repeat(40)}`;
    mismatch(changed);
  }
  mismatch({ ...profile, transferVkSha256: '9'.repeat(64) });
  assert.notEqual(wallet.wtlosReleaseProfileDigest({ ...profile,
    treeVerifierCodeHash: `0x${'9'.repeat(64)}` }), fixture.digest);
});
