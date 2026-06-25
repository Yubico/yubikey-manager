# Yubikit Baseline House Style Audit

Date: 2026-06-24

Scope: `crates/yubikit` source, tests, examples, crate manifest, and crate root.

Reference style: [`docs/yubikit/HOUSE_STYLE.md`](HOUSE_STYLE.md)

Planning ISA: [`docs/yubikit/YUBIKIT_HOUSE_STYLE_AUDIT_ISA.md`](YUBIKIT_HOUSE_STYLE_AUDIT_ISA.md)

# Executive Assessment

`yubikit` is functionally substantial and already has many strong ingredients: typed applet sessions, broad protocol coverage, existing `SecretValue`/`Zeroizing` patterns, meaningful unit tests, hardware integration tests, and a mostly consistent smart-card session shape. The main readiness gap is not lack of domain knowledge; it is uneven agent-shaped implementation texture across modules.

The SDK is not ready to claim house-style conformance yet. It should enter module-by-module remediation, starting with foundational surfaces and cryptographic/secret-handling flows before large applet cleanup.

Primary themes:
- large modules contain too much protocol, type, and helper code for easy review
- secret handling exists but needs full classification of clones, equality, raw byte returns, logs, and temporary buffers
- logging is useful but too application-like in several applets for a security SDK
- error style varies between `thiserror` applets and hand-rolled/generic transport errors
- tests are numerous and often valuable, but cross-module naming, setup, skip/destructive flow, and theatrical-test filtering need consolidation
- DRY opportunities are visible, but most should wait until after local module cleanup

## Mechanical Baseline

Environment: Windows host PowerShell in repo root.

Commands run:

```text
cargo fmt --all -- --check
cargo check -p yubikit
cargo check -p yubikit --no-default-features
cargo check -p yubikit --features pcsc
cargo check -p yubikit --features hid
cargo clippy -p yubikit --all-targets --all-features
cargo test -p yubikit --lib
cargo test -p yubikit --tests --no-run
```

Results:
- formatting: pass
- default feature check: pass
- no-default-features check: pass
- `pcsc` feature check: pass
- `hid` feature check: pass
- library tests: pass, 270 tests
- integration tests: compile pass
- clippy: pass with one warning in test code, `crates/yubikit/src/webauthn/extensions/sign.rs:590`, `search_is_some`

Not run:
- hardware integration execution; requires explicit device/operator setup
- `cargo audit`, `cargo deny`, `cargo miri`; optional tools were not invoked in this pass

Before any module claims remediated readiness, record whether `cargo audit`, `cargo deny`, `cargo miri`, and hardware integration tests were run, skipped for missing tooling/hardware, or intentionally deferred.

## Inventory Hotspots

Largest review surfaces:

| Lines | File |
|---:|---|
| 3007 | `crates/yubikit/src/openpgp.rs` |
| 2925 | `crates/yubikit/src/piv.rs` |
| 2241 | `crates/yubikit/tests/device_tests/fido.rs` |
| 1855 | `crates/yubikit/src/yubiotp.rs` |
| 1784 | `crates/yubikit/src/management.rs` |
| 1420 | `crates/yubikit/src/platform/device.rs` |
| 1390 | `crates/yubikit/src/smartcard.rs` |
| 1352 | `crates/yubikit/tests/device_tests/piv.rs` |
| 1268 | `crates/yubikit/src/keys.rs` |
| 1234 | `crates/yubikit/src/webauthn/client.rs` |
| 1068 | `crates/yubikit/src/securitydomain.rs` |
| 1058 | `crates/yubikit/src/hsmauth.rs` |
| 1033 | `crates/yubikit/src/oath.rs` |
| 1007 | `crates/yubikit/src/webauthn/types.rs` |

## Cross-Cutting Findings

### HS-001: Logging Policy Drift

Severity: medium

Evidence:
- raw traffic logging is correctly isolated in `platform/hidapi.rs` and `platform/pcsc.rs` through `log_traffic!`
- semantic `info!` success logs are common in applets, for example `openpgp.rs:2005`, `openpgp.rs:2156`, `oath.rs:689`, `hsmauth.rs:585`, `management.rs:1042`, `ctap2/session.rs:127`, and `ctap2/large_blobs.rs:184`
- `smartcard.rs:716` logs selected AID at debug using hex; this is probably safe, but should be classified as semantic protocol metadata rather than traffic

Assessment:
The transport traffic policy is good. The semantic log level policy is not yet house-style clean. A security SDK should be quieter than a CLI; success logs should be rare and intentional.

Remediation:
- classify each `info!` as keep/demote/remove
- keep `warn!` only for abnormal-but-recovered states, such as previewSign parse warnings
- document any retained `info!` category in `HOUSE_STYLE.md` if the team chooses to allow it

### HS-002: Secret Equality And Clone Classification Is Incomplete

Severity: high

Evidence:
- `SecretValue` derives `Clone`, `Zeroize`, and `ZeroizeOnDrop` at `__internal/secret.rs:19`
- `SecretValue` implements explicitly non-constant-time `PartialEq` at `__internal/secret.rs:65`
- secret wrapper types derive `Clone`, for example `PivPin` at `piv.rs:693`, `HsmAuthManagementKey` at `hsmauth.rs:118`, and `CredentialPassword` at `hsmauth.rs:158`
- private key structures in `keys.rs` use `SecretValue<Vec<u8>>`, with surrounding public/private key types deriving `Clone` and `PartialEq` in several places

Assessment:
The central wrapper is thoughtful and documented, but every secret-bearing equality and clone path needs classification. This is not necessarily a bug; it is an audit gap.

Remediation:
- create a secret-type inventory
- classify every `Clone` and `PartialEq` on secret-bearing types
- replace convenience-only clones where possible
- verify all adversarial comparisons use `subtle::ConstantTimeEq`, such as OATH response verification and PIV management-key checks

### HS-003: Production `expect`/`unwrap` Needs Invariant Ledger

Severity: medium

Evidence:
- invariant downcast `expect` messages exist in `ctap.rs:186`, `management.rs:1008`, and equivalent YubiOTP backend paths
- constant OID `new_unwrap` appears throughout `keys.rs:41` and `keys.rs:959` onward
- `ctap2/pin_protocol.rs:127` uses `expect("getrandom failed")`
- `ctap2/pin_protocol.rs:164`, `ctap2/pin_protocol.rs:170`, `ctap2/pin_protocol.rs:212`, and `ctap2/pin_protocol.rs:216` use `expect` on HMAC/HKDF operations
- `hsmauth.rs:289`, `hsmauth.rs:351`, and `hsmauth.rs:493` use length-checked unwrap patterns

Assessment:
Many occurrences are likely acceptable invariants. They should be deliberately classified to avoid normalizing panics in device-controlled parsing paths.

Remediation:
- add an invariant ledger per module during remediation
- replace any production panic reachable from malformed device input
- keep compile-time/static invariants with better comments where useful

### HS-004: Error Style Is Mixed

Severity: medium

Evidence:
- applet errors generally use `thiserror` and `#[non_exhaustive]`, for example `PivError` at `piv.rs:79`, `OathError` at `oath.rs:219`, `OpenPgpError` at `openpgp.rs:113`, `HsmAuthError` at `hsmauth.rs:303`, and `SecurityDomainError` at `securitydomain.rs:61`
- lower-level/generic errors are mixed: `DeviceError` is hand-rolled at `device.rs:46`, `CtapError` is hand-rolled at `ctap.rs:62`, `ClientError` is hand-rolled at `webauthn/client.rs:38`, `KeyError` is a string wrapper at `keys.rs:1086`, and `OtpError` lacks `#[non_exhaustive]` at `otp.rs:127`

Assessment:
Some hand-rolled/generic errors may be justified by generic transport parameters. The audit should decide which are intentional API shape and which are style drift.

Remediation:
- define public error policy per layer: applet, transport, parser, WebAuthn client
- add `#[non_exhaustive]` where public error enums may grow
- preserve source errors where possible
- avoid broad string errors for cases that matter to callers

### HS-005: Tests Are Numerous But Need Value Classification

Severity: medium

Evidence:
- pure library test suite is substantial and passes 270 tests
- examples and hardware tests are broad, especially `tests/device_tests/fido.rs` and `tests/device_tests/piv.rs`
- clippy warning exists in a test assertion in `webauthn/extensions/sign.rs:590`
- hardware test harness uses skip macros and environment-driven device selection, but per-module naming/setup/cleanup consistency still needs review

Assessment:
The SDK is not under-tested. The issue is consistency and value classification. Some tests are strong protocol/parser tests; others need review for constructor-only or roundtrip-only theatre.

Remediation:
- standardize behavior-first names
- classify tests as vector, parser-edge, device-behavior, regression, harness, or theatrical
- converge hardware setup, skip, destructive marker, and cleanup conventions
- fix the clippy warning in `sign.rs:590`

### HS-006: Consolidation Should Be Deferred But Tracked

Severity: medium

Evidence:
- session constructors repeat applet selection, SCP setup, and recoverable connection return patterns across PIV, OpenPGP, OATH, HSM Auth, Security Domain, CTAP, Management, and YubiOTP
- APDU/TLV/status-word/retry parsing patterns recur across PIV, OpenPGP, HSM Auth, OATH, Security Domain, and SmartCard
- multi-backend downcast patterns recur in CTAP, Management, and YubiOTP

Assessment:
There are real helper opportunities, but first-pass extraction risks hiding protocol semantics. Track candidates now; extract after local cleanup.

Remediation:
- create a second-pass consolidation backlog
- prefer helpers for repeated invariants only: retry extraction, APDU framing, backend recovery, test harness setup, secret buffer construction

## Module Assessments

Each module remediation should add explicit firmware-gate and protocol-compat notes. If none are found, record "no firmware gates found" or "no serialized protocol compatibility risks found" rather than leaving the category implicit.

### `lib`

Files:
- `crates/yubikit/src/lib.rs`
- `crates/yubikit/Cargo.toml`

Assessment:
- crate docs are clear and align with SDK positioning
- crate root uses `#![warn(missing_docs)]`, which is appropriate
- README references a `hardware` default feature, but `Cargo.toml` defines `default = ["pcsc", "hid"]`; this is a concrete documentation drift
- public modules include `__internal` as hidden but public; audit whether this is necessary for crate-internal access or should be `pub(crate)`/hidden only

Remediation:
- fix README/feature documentation drift
- classify public module exports and confirm no accidental stabilization of internals
- add crate-root API review to every public API change

### `core`

Files:
- `crates/yubikit/src/core.rs`

Assessment:
- small foundational module with `Version`, `Connection`, `Transport`, and helpers
- good home only for substrate-level concepts
- version override and feature-gate helpers are cross-cutting and should receive tests/documentation scrutiny

Remediation:
- do not add convenience helpers here during first-pass remediation
- second-pass only: consider moving truly repeated invariants here if they are independent of APDU/HID specifics

### `logging`

Files:
- `crates/yubikit/src/logging.rs`

Assessment:
- `log_traffic!` establishes a useful `traffic::` trace target
- `hex_encode` is simple and adequate
- policy problem is call-site usage, not helper implementation

Remediation:
- keep implementation minimal
- audit all call sites against the logging policy before adding new helpers

### `__internal`

Files:
- `crates/yubikit/src/__internal/secret.rs`
- `crates/yubikit/src/__internal/tlv.rs`
- `crates/yubikit/src/__internal/mod.rs`

Assessment:
- `SecretValue` redacts `Debug` and `Display` and zeroizes on drop
- `into_inner` uses unsafe ownership transfer and requires high-scrutiny review
- non-constant-time `PartialEq` is documented, but downstream use must be proven non-adversarial
- TLV tests include malformed/truncated/oversized cases, which is strong

Remediation:
- add safety/invariant review for `into_inner`
- classify every downstream `SecretValue` equality use
- keep TLV helpers internal and parser-focused

### `keys`

Files:
- `crates/yubikit/src/keys.rs`
- `crates/yubikit/tests/device_tests/arkg_p256.rs`

Assessment:
- private key fields use `SecretValue`, which is the right direction
- OID constants use `new_unwrap`, likely acceptable compile-time invariants
- public/private key structs derive `Clone`, `PartialEq`, and `Debug` in many places; secret-bearing derives need careful classification
- parser tests skew toward SPKI roundtrips; malformed DER cases need explicit review

Remediation:
- inventory all secret-bearing private-key structs and derived traits
- add malformed DER/PKCS parser tests where gaps exist
- classify OID unwraps as static invariants

### `cbor`

Files:
- `crates/yubikit/src/cbor.rs`

Assessment:
- compact CBOR helper with canonical ordering tests and malformed input tests
- `Debug` displays byte strings as hex; safe for public bytes but can leak if secret-bearing `Value::Bytes` is logged/debugged elsewhere

Remediation:
- audit CBOR debug/log call sites in WebAuthn/CTAP2
- add or confirm negative tests for unsupported/indefinite/oversized forms if protocol requires rejection

### `smartcard`

Files:
- `crates/yubikit/src/smartcard.rs`

Assessment:
- foundational APDU/SCP module; changes here have high blast radius
- AID documentation for PIV field behavior is valuable and should be preserved
- `ScpKeyParams`, `Dek`, and `ScpState` use zeroization/redacted debug patterns
- `info!("SCP secure channel established")` should be reviewed under library logging policy
- status-word mapping is a candidate source for applet-level consistency

Remediation:
- perform dedicated SCP lifecycle trace
- classify APDU logging and status-word mapping as possible second-pass helper sources
- review SCP/session lifetime interactions across applets

### `platform`

Files:
- `crates/yubikit/src/platform/*.rs`

Assessment:
- raw HID/PCSC traffic logging uses `log_traffic!`, which matches policy
- Windows SetupDI contains necessary FFI unsafe blocks and needs explicit safety-comment audit
- `platform/device.rs` is large and likely mixes enumeration, merge, identity, and platform policy
- `platform/pcsc.rs` has at least one logically guarded `unwrap` pattern that should be classified

Remediation:
- audit all unsafe blocks in `setupdi.rs`
- classify PCSC/HID error preservation and no-panic behavior
- consider local decomposition of platform device enumeration only after tests pin behavior

### `device`

Files:
- `crates/yubikit/src/device.rs`

Assessment:
- device identity, preview firmware, and fallback synthesis logic are correctness-sensitive
- debug logging around fallback/synthesis is useful, but wording/level should be standardized
- tests cover preview/SKY/product inference behavior, which is valuable

Remediation:
- document identity/reinsert invariants
- align fallback logs with policy
- keep product inference tests as regression anchors

### `management`

Files:
- `crates/yubikit/src/management.rs`

Assessment:
- large multi-transport module with backend pattern similar to CTAP/YubiOTP
- generic `ManagementError` is likely justified but should be documented as layer policy
- `info!` logs for reset/config write/USB mode are questionable in a library
- many tests cover parsing and config bytes; review for behavior-first naming and edge cases

Remediation:
- classify all operation logs
- compare backend/downcast pattern with CTAP/YubiOTP and decide whether a second-pass helper is warranted
- audit config lock/reset paths and destructive test markers

### `otp`

Files:
- `crates/yubikit/src/otp.rs`

Assessment:
- compact HID framing and modhex/CRC module
- error enums lack the same `#[non_exhaustive]` posture as most applet errors
- tests cover CRC, modhex, frame size, and sequence behavior

Remediation:
- decide public error enum extensibility policy
- keep low-level OTP protocol separate from YubiOTP applet semantics

### `yubiotp`

Files:
- `crates/yubikit/src/yubiotp.rs`
- `crates/yubikit/tests/device_tests/yubiotp.rs`

Assessment:
- large module with slot programming, config building, NDEF, HMAC/HOTP/static password support
- secret material includes AES keys, private IDs, access codes, HMAC keys, and static-password material
- backend/downcast/session pattern should be compared with Management and CTAP
- tests cover config building and slot behavior, but hardware destructive flow needs consistency review

Remediation:
- create secret inventory for slot configuration types
- classify config builder tests for real behavior vs implementation echo
- track backend helper as second-pass candidate

### `oath`

Files:
- `crates/yubikit/src/oath.rs`
- `crates/yubikit/tests/device_tests/oath.rs`

Assessment:
- strong use of `OathAccessKey`, `Zeroizing`, PBKDF2/HMAC helpers, and constant-time response comparison
- SHA-1/HMAC is protocol-required but should be consistently documented as such
- success `info!` logs should be reviewed
- tests cover access-key lifecycle and OATH behavior; classify vector coverage and hardware cleanup

Remediation:
- audit credential secret lifetime and manual drop paths
- normalize logging
- standardize test names and setup with other applets

### `hsmauth`

Files:
- `crates/yubikit/src/hsmauth.rs`
- `crates/yubikit/tests/device_tests/hsmauth.rs`

Assessment:
- good secret wrapper usage for management keys and credential passwords
- clone derives on secret wrappers need classification
- length-checked unwraps likely represent invariants but need ledger entries
- `SessionKeys` parsing and password-to-key derivation require end-to-end secret trace

Remediation:
- trace symmetric and asymmetric credential flows
- classify all `Zeroizing` buffers and clones
- review management-key retry and wrong-password error mapping against PIV/OpenPGP

### `securitydomain`

Files:
- `crates/yubikit/src/securitydomain.rs`
- `crates/yubikit/tests/device_tests/securitydomain.rs`

Assessment:
- SCP and certificate/allowlist operations are high sensitivity
- static/default key handling and KCV computation need explicit protocol rationale
- tests cover SCP03/SCP11 paths but destructive/reset and allowlist state need clear gating

Remediation:
- trace SCP03/SCP11 key lifecycle with `smartcard`
- classify certificate and allowlist trust semantics
- defer helper extraction until `smartcard` and applet audits agree on invariants

### `piv`

Files:
- `crates/yubikit/src/piv.rs`
- `crates/yubikit/tests/device_tests/piv.rs`

Assessment:
- very large but domain-rich module
- `PivPin` and management key handling use secret wrappers/zeroizing, but clones/equality and temporary buffers need classification
- broad key algorithm support, including PQC, increases firmware-gate and parser risk
- many APDU/TLV patterns likely overlap with OpenPGP/HSM Auth/Security Domain

Remediation:
- do not split prematurely; first inventory internal sections and secret flows
- trace management-key auth, PIN/PUK, key import, signing/decryption/ECDH/KEM
- standardize logging and retry mapping
- after local cleanup, identify APDU/TLV helper candidates

### `openpgp`

Files:
- `crates/yubikit/src/openpgp.rs`
- `crates/yubikit/tests/device_tests/openpgp.rs`

Assessment:
- largest source file and a major style-readiness hotspot
- many `info!` success logs for PIN, reset code, KDF, reset, key generation/import/delete, certificate import/delete
- PIN/admin PIN/reset code/private key import flows require secret tracing
- KDF and algorithm attributes need spec-linked clarity

Remediation:
- start with logging cleanup/classification
- trace PIN/admin PIN/reset-code and private-key import flows
- compare retry/PIN handling with PIV and HSM Auth
- consider local section extraction only after behavior is pinned by tests

### `fido` and `ctap`

Files:
- `crates/yubikit/src/fido.rs`
- `crates/yubikit/src/ctap.rs`

Assessment:
- `fido.rs` is compact and mostly transport abstraction
- `CtapError` is hand-rolled and generic; likely intentional but should be documented
- backend/downcast invariant `expect` needs ledger classification
- CTAP over smartcard/NFC and HID should be reviewed for consistent error and cancellation semantics

Remediation:
- classify generic error style
- compare backend pattern with Management/YubiOTP
- test malformed APDU/HID response paths where practical

### `ctap2`

Files:
- `crates/yubikit/src/ctap2/*.rs`

Assessment:
- `pin_protocol.rs` is the highest-priority crypto review target in CTAP2
- PIN/UV tokens are wrapped with `Zeroizing` in several submodules, which is good
- `encrypt`, `decrypt`, and `authenticate` return raw `Vec<u8>` and assume caller-provided key lengths; public or crate-visible boundaries need review
- `getrandom` and HKDF/HMAC `expect` choices need explicit invariant/risk classification
- submodules use `#[allow(clippy::result_large_err)]` repeatedly, likely due generic connection error shape

Remediation:
- perform full PIN/UV protocol lifecycle trace
- validate key lengths before indexing where caller-controlled
- classify raw byte outputs as secret/token/ciphertext/public
- decide whether repeated large-error allowances indicate an API shape problem or acceptable tradeoff

### `webauthn`

Files:
- `crates/yubikit/src/webauthn/*.rs`
- `crates/yubikit/src/webauthn/extensions/*.rs`
- `crates/yubikit/examples/webauthn*.rs`

Assessment:
- high-level API is broad and example-heavy
- `webauthn/client.rs` is large and should be reviewed for ceremony flow clarity and security boundary visibility
- previewSign extension is explicitly preview/unstable and uses warn logs for parse failures
- examples use user-facing output, including non-ASCII symbols; acceptable for examples but inconsistent with austere SDK style
- PRF examples print derived secret-like outputs in hex; useful for demo, but risky as a copy-paste pattern

Remediation:
- classify WebAuthn extension outputs as public/secret/opaque
- review examples for safe copy-paste behavior, especially PRF/largeBlob outputs
- fix clippy warning in `extensions/sign.rs:590`
- consider API stability markers for previewSign

### Examples And Test Harness

Files:
- `crates/yubikit/examples/*.rs`
- `crates/yubikit/examples/example_utils.rs`
- `crates/yubikit/tests/device_tests.rs`
- `crates/yubikit/tests/device_tests/*.rs`

Assessment:
- hardware harness has useful skip macros and environment setup
- examples are practical, but several use emoji/checkmark output and print sensitive-looking outputs for demos
- `example_utils.rs` is a shared pattern source and should be treated as user-copyable code
- large hardware tests prove real behavior, but setup/destructive/cleanup consistency needs review

Remediation:
- standardize hardware test naming, skip reasons, destructive markers, and cleanup
- remove or justify example output of derived secret-like material
- make shared example utility patterns conservative and copy-paste safe

## Prioritized Remediation Backlog

1. Fix documentation drift in `crates/yubikit/README.md` around the non-existent `hardware` feature.
2. Fix clippy warning in `webauthn/extensions/sign.rs:590`.
3. Create secret inventory: `SecretValue`, `Zeroizing`, `ZeroizeOnDrop`, manual `Drop`, clone, equality, debug/display, log/error/panic surfaces.
4. Classify and normalize `info!` logging across applets.
5. Build invariant ledger for production `unwrap`/`expect`/`unsafe`/`allow` occurrences.
6. Perform CTAP2 PIN/UV protocol lifecycle review.
7. Perform SCP lifecycle review across `smartcard`, `securitydomain`, and applets using SCP.
8. Normalize error policy by layer.
9. Standardize hardware test harness style and classify theatrical tests.
10. After module-local remediation, run second-pass consolidation audit for APDU, retry/status, session constructor, secret-buffer, and test harness helpers.

Backlog item 3 is a gate for secret-adjacent module remediation. Applet modules that handle PINs, passwords, access keys, management keys, private keys, shared secrets, PIN/UV tokens, session keys, PRF outputs, or static-password material should not claim readiness until the secret inventory classification is complete for that module.

## Cato Review Status

The house-style plan and audit ISA passed Cato-style external review using `claude --model opus --permission-mode plan`. Provider/Vertex configuration was not inspectable from CLI output. First review returned medium concerns; revisions addressed crate-root scope, constant-time criteria, test-theatre definition, audit order, tooling baseline, crypto depth, firmware/compat/SCP criteria, and shared test/example utilities. Second review returned `pass` with non-blocking info items, which were incorporated.

The completed baseline audit also passed Cato-style external review with low criticality and no blocking findings. For the final readiness audit, preserve the external review transcript or attach it as an artifact so the review chain is independently verifiable.

## Readiness Verdict

Baseline readiness: concerns.

The project has strong functional foundations and passes non-destructive mechanical checks, but it does not yet conform to the new house style. Proceed with staged module-by-module remediation using this audit and `HOUSE_STYLE.md` as the benchmark.
