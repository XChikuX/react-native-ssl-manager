# Project Context

## Purpose

`react-native-ssl-manager` is a production-ready SSL certificate pinning library
for React Native and Expo. It protects apps against man-in-the-middle (MITM)
attacks using platform-native enforcement:
- **iOS**: [TrustKit](https://github.com/datatheorem/TrustKit) with swizzled
  `URLSession` delegates.
- **Android**: OkHttp `CertificatePinner` + auto-generated
  `network_security_config.xml`.

Version 2.0 is built as a [Nitro Module](https://nitro.margelo.com), requiring
React Native 0.75+ (New Architecture) and `react-native-nitro-modules`.

## Tech Stack

- **TypeScript** — public API (`src/index.ts`) and Nitro HybridObject spec
  (`src/specs/SslManager.nitro.ts`)
- **Swift** — iOS native module (`ios/`) with TrustKit
- **Kotlin** — Android native module (`android/`) with OkHttp + NSC
- **Nitro Modules** — native bridge; `nitrogen` generates `nitrogen/` bindings
  from the TypeScript spec. Run `yarn specs` after changing the spec.
- **Expo Config Plugin** — `app.plugin.js` (TypeScript compiled to `plugin/`)
- **Jest** — unit tests (`__tests__/`, run with `expo-module test`)
- **Yarn Berry (3.6.1)** — package manager; use `yarn`, not `npm`

## Project Conventions

### Code Style
- **Formatting**: Prettier with `singleQuote: true`, `tabWidth: 2`, `trailingComma: 'es5'`
- **Linting**: ESLint (`@react-native` + prettier); run `yarn lint`
- **TypeScript**: strict; `yarn typecheck` must pass

### Architecture Patterns
- The native API surface is defined in `src/specs/SslManager.nitro.ts`.
  Any new native method must be added there and `yarn specs` re-run.
- Pinning is initialized **eagerly at app launch** (not lazily via JS module
  construction). iOS uses an ObjC `+load` bootstrap; Android uses
  `androidx.startup`.
- All public JS functions throw (not no-op) when the native module is not linked.
  Guard with `isSSLManagerAvailable()`.
- The `TrustEngine` class (`src/TrustEngine.ts`) is a pure-TypeScript
  policy layer — it does not replace native pinning but layers on top.
- Android NSC pins **never expire** (no `pin-set expiration`); removal of
  expiry was a deliberate security decision (v1.1.3+).

### Testing Strategy
- Unit tests live in `__tests__/` and use the Jest `react-native` preset.
- Run: `yarn test`
- Tests use plain JavaScript to validate logic without requiring TypeScript compilation.
- Native behavior is tested via example apps (`example/`, `example-expo/`).

### Git Workflow
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`
- Pre-commit hooks enforce commit message format and run linter + tests.
- Use `yarn release` (release-it) for publishing.

## Domain Context

- `ssl_config.json` is the single config file: a map of domain → SHA-256 SPKI
  pins (prefixed `sha256/`). Always include ≥ 2 pins per domain.
- iOS runtime changes (disable pinning, update config) take effect on the **next
  app launch** (TrustKit limitation); Android applies changes immediately.
- `PinnedOkHttpClient` (Kotlin singleton) is the public Android API for native
  modules that need a pinned OkHttp client outside React Native's networking layer.

## Important Constraints

- Requires New Architecture (RN 0.75+) and `react-native-nitro-modules` peer dep.
- iOS: `pod install` required after native changes; podspec is `NitroSslManager`.
- Android: `compileSdk` 34+, NDK 27+, Xcode 16.4+ for iOS builds.
- The `nitrogen/` directory is auto-generated — do not edit it by hand.
- Pins never expire on Android (fail-open expiry was removed as a security fix).

## External Dependencies

- [TrustKit](https://github.com/datatheorem/TrustKit) — iOS SSL pinning
- [react-native-nitro-modules](https://nitro.margelo.com) — native bridge
- [OkHttp](https://square.github.io/okhttp/) — Android HTTP client
- [androidx.startup](https://developer.android.com/topic/libraries/app-startup) — Android eager init
