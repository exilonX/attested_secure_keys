# attested_secure_keys — workspace

Monorepo for **`attested_secure_keys`**, a Flutter library for hardware-backed,
attestable EC P-256 keys (Android Keystore/StrongBox · iOS Secure Enclave),
non-exportable, with server-verifiable key attestation.

It's a **pub workspace** — run `flutter pub get` once at the repo root to resolve
every package together.

## Layout

```
.
├─ HW_KEYS_FLUTTER_LIB_SPEC.md                  # product specification (design source of truth)
├─ pubspec.yaml                                 # pub workspace root
├─ .github/workflows/                           # ci.yml · publish.yml · device-tests.yml
└─ packages/
   ├─ attested_secure_keys/                     # app-facing facade (+ example app)
   ├─ attested_secure_keys_platform_interface/  # contract + normalized model + Pigeon schema
   ├─ attested_secure_keys_android/             # Kotlin — first-party Keystore + androidx.biometric
   ├─ attested_secure_keys_ios/                 # Swift — first-party Secure Enclave + App Attest
   └─ attested_secure_keys_verifier/            # Node/TS server-side verifier (M2, skeleton)
```

App developers depend only on **`attested_secure_keys`**; it endorses the
platform packages. The verifier is a separate Node package (not part of the pub
workspace).

## Getting started

```bash
# From the repo root (resolves the whole pub workspace):
flutter pub get
flutter analyze
cd packages/attested_secure_keys && flutter test

# Regenerate the typed channel bindings after editing the Pigeon schema:
cd packages/attested_secure_keys_platform_interface
dart run pigeon --input pigeons/messages.dart

# Run the example (real device recommended for the hardware paths):
cd packages/attested_secure_keys/example && flutter run

# Server-side verifier:
cd packages/attested_secure_keys_verifier && npm install && npm test
```

See [`packages/attested_secure_keys/README.md`](packages/attested_secure_keys/README.md)
for usage/API, [`packages/attested_secure_keys_verifier/README.md`](packages/attested_secure_keys_verifier/README.md)
for server verification, and [`HW_KEYS_FLUTTER_LIB_SPEC.md`](HW_KEYS_FLUTTER_LIB_SPEC.md)
for the full design.

## License

Apache-2.0.
