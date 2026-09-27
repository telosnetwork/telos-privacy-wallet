// Generate the fixture with the exact relayer profile builder, not a copy of
// its serialization rules. Run with WTLOS_RELAYER_ROOT set to a reviewed
// checkout. This script never contacts a service or blockchain.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const ts = require('typescript');

const relayerRoot = process.env.WTLOS_RELAYER_ROOT;
if (!relayerRoot) throw new Error('WTLOS_RELAYER_ROOT is required');
const dirty = execFileSync('git', ['-C', relayerRoot, 'status', '--porcelain', '--untracked-files=no'],
  { encoding: 'utf8' });
if (dirty.trim()) throw new Error('Relayer checkout has uncommitted source changes');
require.extensions['.ts'] = (module, filename) => {
  const source = fs.readFileSync(filename, 'utf8');
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
      esModuleInterop: true }, fileName: filename,
  });
  module._compile(compiled.outputText, filename);
};

const builderPath = path.join(relayerRoot, 'zp-relayer/pool/WTLOSOnlyReleaseProfile.ts');
const builder = require(builderPath);
const hash = byte => byte.repeat(64);
const tree = byte => byte.repeat(40);
const evmHash = byte => `0x${hash(byte)}`;
const address = byte => `0x${byte.repeat(40)}`;
const profile = builder.buildWTLOSOnlyReleaseProfile(
  address('1'), '40003', {
    circuitSourceTree: tree('a'), contractSourceTree: tree('b'),
    ceremonyManifestSha256: hash('e'),
  }, {
    implementation: address('2'), proxyCodeHash: evmHash('a'),
    implementationCodeHash: evmHash('b'), transferVerifier: address('3'),
    transferVerifierCodeHash: evmHash('c'), treeVerifier: address('4'),
    treeVerifierCodeHash: evmHash('d'),
  }, hash('1'), hash('2'), tree('f')
);
const fixture = {
  producerCommit: execFileSync('git', ['-C', relayerRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  producerTree: execFileSync('git', ['-C', relayerRoot, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' }).trim(),
  producerModule: 'zp-relayer/pool/WTLOSOnlyReleaseProfile.ts',
  producerModuleSha256: crypto.createHash('sha256').update(fs.readFileSync(builderPath)).digest('hex'),
  profile,
  digest: builder.wtlosOnlyReleaseProfileDigest(profile),
};
const target = path.join(__dirname, 'relayer-v2-profile.json');
if (process.argv.includes('--write')) {
  fs.writeFileSync(target, `${JSON.stringify(fixture, null, 2)}\n`);
} else {
  const existing = JSON.parse(fs.readFileSync(target, 'utf8'));
  if (JSON.stringify(existing) !== JSON.stringify(fixture)) {
    throw new Error('Relayer v2 fixture differs from reviewed builder output');
  }
}
console.log(`${fixture.producerCommit} ${fixture.digest}`);
