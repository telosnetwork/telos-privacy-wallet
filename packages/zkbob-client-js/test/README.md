# WTLOS release-profile v2 compatibility

`fixtures/relayer-v2-profile.json` is a synthetic profile emitted by the
relayer's `buildWTLOSOnlyReleaseProfile` at the recorded commit, tree and
builder source SHA-256. The fixture's digest comes from the relayer's own
SHA-256 function. No address or hash in the fixture is a production deployment
pin.

With dependencies installed, run `yarn workspace zkbob-client-js
test:wtlos-release-profile`. To recheck the fixture against the same reviewed
relayer checkout, set `WTLOS_RELAYER_ROOT` to that checkout and run
`node test/fixtures/generate-relayer-v2-profile.cjs` from this package. The
script compares the complete fixture, including source commit and tree; pass
`--write` only when deliberately regenerating for a newly reviewed relayer
source. Neither test asserts deployed code, ceremony qualification, or an
approved release.
