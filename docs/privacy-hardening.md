# Wallet privacy hardening

This patch keeps private transaction witnesses on the user's device, removes automatic wallet telemetry, and restores desktop certificate validation. It also aligns desktop proving parameters with the active pool's parameter alias.

## Behavior changes

- Account login, demo login, and gift redemption use local proving. Official production and development configurations have no delegated prover endpoints. The SDK's delegated prover API still exists for other integrations.
- Desktop proving no longer logs its inputs. Native failures return a generic error without forwarding the original exception to the renderer or console.
- Desktop certificate errors are rejected, including in development. Use valid or locally trusted certificates for development endpoints.
- Desktop IPC receives the active `prod` or `staging` parameter alias. The main process selects only an allowlisted bundled file, caches each parsed set, and rejects unknown aliases. The client still verifies the returned proof against the active verification key.
- The support context no longer requests the user's public IP or tags Sentry. The locally displayed support identifier is no longer passed to SDK network clients.
- Route initialization no longer starts Sentry or navigation tracing. Existing `captureException` calls have no initialized Sentry transport in this application.

Local proving may increase gift redemption time and memory use. Devices that cannot prove locally must show an error; restoring remote witness submission is not an acceptable silent fallback. Automatic crash reports are unavailable after this change.

This does not provide network anonymity. RPCs, relayers, WalletConnect, asset hosts, and optional bridge services can still observe connection metadata. It does not change pool contracts or establish the provenance of bundled cryptographic parameters.

## Focused regression checks

With the normal workspace dependencies installed, run from the repository root:

```sh
node --test scripts/privacy-hardening.test.cjs
git diff --check
```

The focused tests execute selected application functions with mocked React, SDK, filesystem, Electron, and native-prover boundaries. They check privacy behavior and parameter selection without requiring a Rust build or submitting transactions.

For an isolated run without the full workspace build, install only test transformation dependencies outside the repository:

```sh
privacy_test_runtime=$(mktemp -d)
npm install --prefix "$privacy_test_runtime" --ignore-scripts --no-audit --no-fund @babel/core@7.29.7 @babel/preset-react@7.29.7 @babel/plugin-transform-modules-commonjs@7.29.7
NODE_PATH="$privacy_test_runtime/node_modules" node --test scripts/privacy-hardening.test.cjs
```

Results on 2026-09-16: 12/12 checks pass on the patch. The same checks fail 12/12 against the original source at `4354c9c279eb40c3a4164d97695985124285d9ce`:

```sh
PRIVACY_TEST_REF=4354c9c279eb40c3a4164d97695985124285d9ce node --test scripts/privacy-hardening.test.cjs
```

These results are regression evidence, not a cryptographic audit or a complete application integration test.

## Required before release

1. Build the SDK, WASM, web app, and packaged Electron app using the repository's pinned toolchain; run the existing suite and lint checks. These full builds were not available in the isolated review environment.
2. In testnet, exercise normal transfers, gift redemption, demo login, pool switching, restoration, and error handling in web and packaged desktop builds. Verify actual native proofs against the matching deployed verifier, and verify that the production bundle selects the production parameter set. The new IPC payload requires the renderer, SDK, and Electron main process to be released together.
3. Inspect network traffic with synthetic accounts: no support-context IP lookup, Sentry request, `zkbob-support-id` identifier, or delegated-prover request should occur. Confirm private witnesses and gift secrets are absent from logs and exported diagnostics.
4. Verify certificate rejection against an invalid-certificate test endpoint, and test both `prod` and `staging` parameter aliases. Record cold/warm proving latency and peak memory on supported devices.
5. Pin and independently authenticate proving parameters and verification keys against the deployed contract manifest. This patch corrects file selection only.

No contract deployment, parameter rotation, or wallet release is included in this patch.
