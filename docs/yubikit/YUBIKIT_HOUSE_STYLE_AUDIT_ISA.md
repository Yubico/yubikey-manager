# Yubikit House Style And Readiness Audit ISA

This ISA is the handoff PRD for auditing `crates/yubikit` against the canonical house style in [`docs/yubikit/HOUSE_STYLE.md`](HOUSE_STYLE.md). It is written for a future engineer agent that will perform the baseline audit, then later remediate modules one at a time.

## Problem

`crates/yubikit` is broad, security-sensitive Rust SDK code spanning smart card applets, FIDO/CTAP, WebAuthn, OTP HID, platform transports, key parsing, CBOR/TLV helpers, and hardware integration tests. Much of it was written by one strong developer with AI agent assistance. That creates a predictable risk profile: correct domain intent mixed with uneven agent-generated patterns, inconsistent logging, theatrical tests, duplicated session/APDU idioms, inconsistent error shapes, and secret-handling patterns that must be verified rather than assumed.

The current namespace needs an industry-grade house style and readiness audit so future remediation can improve the SDK without overwriting intentional protocol-specific design.

## Vision

The whole `crates/yubikit` namespace should read as if one expert 30+ year C/Rust hardware-security developer wrote it: minimal, consistent, spec-faithful, unsurprising, and easy to review. A skeptical SDK maintainer should find the audit useful, specific, and free of hype.

## Out Of Scope

This ISA does not authorize behavior-changing remediation during the baseline audit. It does not require immediate public API redesign, cryptographic primitive replacement, broad module splitting, or helper extraction unless a concrete safety, correctness, or maintainability issue is found. It does not run destructive hardware tests without explicit operator approval. It does not chase formatting churn unrelated to readiness.

If the baseline audit discovers an active exploitable vulnerability, data-leak risk, or unsafe destructive-operation risk, escalate to the operator immediately instead of deferring the issue to Phase 2 remediation.

## Principles

- Define the target style before judging conformity.
- Prefer local cleanup before cross-module abstraction.
- Preserve applet-specific protocol semantics where they differ.
- Treat tests as evidence, not ceremony.
- Treat logs and error messages as security-relevant surfaces.
- Make findings concrete enough for future agents to remediate without rediscovery.
- Do not use AI-style homogenization as a substitute for engineering judgment.

## Constraints

- Canonical house style lives at repo level: `docs/yubikit/HOUSE_STYLE.md`.
- Baseline audit covers all Rust code under `crates/yubikit`, including applets, transports, helpers, examples, and tests.
- Audit output must include per-module findings and remediation tasks.
- Remediation is staged module-by-module after the baseline audit.
- A second-pass consolidation audit happens after all modules have passed through first-pass remediation.
- A final readiness audit happens after consolidation.
- Cato-style cross-vendor review is required before treating the plan or final audit as ready.
- Implementation workflow begins with an Operator Interview that records autonomy, hardware, user-presence, destructive-test, commit, and quality-gate policy before Phase 0.
- Every implementation phase uses an Engineer/Reviewer loop, with Cato reserved for written-artifact audits.
- Runtime Cato artifacts are left visible for Operator inspection and are not staged or committed unless explicitly approved.

## Goal

Produce a reusable house style and a module-by-module readiness audit plan that future engineers can execute to bring `crates/yubikit` into a consistent, minimal, security-conscious SDK style. The handoff must identify exactly what to assess, how to judge it, and how to remediate each module without premature over-abstraction.

## Criteria

- [x] ISC-HS-1: `docs/yubikit/HOUSE_STYLE.md` exists and defines module shape, API design, error handling, session construction, secret handling, cryptography, protocol code, logging, testing, documentation, unsafe code, dependencies, and consolidation policy.
- [x] ISC-HS-2: House style explicitly values less code, minimal abstraction, protocol-specific correctness, and non-theatrical tests.
- [x] ISC-HS-3: House style includes a logging policy that forbids secret-bearing logs and confines raw APDU/HID bytes to `traffic::` logging.
- [x] ISC-HS-4: House style includes a testing policy requiring tests to prove real behavior with consistent naming, setup, skip, destructive-marker, and cleanup flow.
- [x] ISC-AUD-1: Baseline audit covers every `crates/yubikit/src` namespace and `crates/yubikit/tests`/`examples` surfaces that affect house-style readiness.
- [x] ISC-AUD-2: Every module assessment includes code smells, best-practice deviations, crypto/secret-safety concerns, DRY/consolidation opportunities, coding-style deviations, logging concerns, test concerns, and remediation tasks.
- [x] ISC-AUD-3: Every finding includes concrete file references and a severity or readiness impact.
- [x] ISC-AUD-4: Every remediation task is scoped to be executable independently where feasible.
- [ ] ISC-SEC-1: Secret-bearing values are classified and checked for `SecretValue`, `Zeroizing`, `ZeroizeOnDrop`, or justified manual zeroization.
- [ ] ISC-SEC-2: `Debug`, `Display`, logs, errors, and panics are checked for secret leakage.
- [ ] ISC-SEC-3: Crypto code is checked for key length validation, RNG behavior, KDF/MAC/encryption parameters, firmware/version gates, and protocol-required legacy algorithms.
- [ ] ISC-SEC-4: Every `PartialEq` implementation or derive on secret-bearing types is classified as constant-time, explicitly non-adversarial, or incorrect.
- [ ] ISC-SEC-5: Every `Clone` implementation or derive on secret-bearing types is classified as protocol/API-required, convenience-only, or incorrect.
- [ ] ISC-ERR-1: Error handling is checked for applet consistency, source preservation, status-word mapping, PIN retry semantics, and avoidance of ambiguous `String` errors where typed context matters.
- [ ] ISC-LOG-1: Logging is checked for level consistency, message usefulness, no secret leakage, raw traffic isolation, and questionable library-level `info!` success messages.
- [ ] ISC-TST-1: Tests are checked for real behavioral value rather than coverage theatre.
- [ ] ISC-TST-2: Tests across modules are checked for consistent abstractions, naming, setup flow, skip behavior, destructive markers, and cleanup.
- [ ] ISC-DRY-1: Duplication is classified as either intentional protocol locality, local cleanup candidate, or second-pass consolidation candidate.
- [x] ISC-API-1: `crates/yubikit/src/lib.rs` is audited for crate docs, public module surface, feature-gate consistency, lint posture, and whether exports match intended SDK boundaries.
- [x] ISC-FEAT-1: Supported feature combinations are checked for compile viability: default features, `--no-default-features`, `--features pcsc`, and `--features hid`.
- [x] ISC-TOOL-1: Mechanical tooling baseline is recorded before manual findings are finalized: formatting status, clippy status, available dependency/security audit tooling, and hardware-test availability.
- [ ] ISC-FW-1: Firmware/version gates are checked against a cited source: existing code comments, Yubico documentation, protocol specs, or explicitly documented field-test evidence.
- [ ] ISC-COMPAT-1: CBOR, TLV, DER, APDU, HID, and serialized/deserialized protocol formats are checked for compatibility risks across supported firmware/protocol versions.
- [ ] ISC-SCP-1: SCP secure-channel state and applet session lifetime interactions are reviewed across `smartcard`, `securitydomain`, `piv`, `openpgp`, `hsmauth`, `management`, and `ctap` over CCID/NFC.
- [x] ISC-LIFE-1: Audit lifecycle defines baseline audit, module remediation, second-pass consolidation audit, and final readiness audit.
- [x] ISC-LIFE-2: Second-pass audit explicitly looks for helper/core opportunities surfaced only after all modules have been remediated once.
- [x] ISC-CATO-1: Cato-style external review checks that this plan is concrete, complete, non-theatrical, and safe for future remediation.
- [ ] ISC-OP-1: Workflow begins with a documented Operator Interview before implementation.
- [ ] ISC-OP-2: Operator answers are persisted to `docs/yubikit/OPERATOR_CONTEXT.local.md` and treated as local by default.
- [ ] ISC-OP-3: Autonomy level, hardware availability, destructive-test approval, user-presence/controller availability, commit policy, and quality gates are recorded before Phase 0.
- [ ] ISC-LOOP-1: Every implementation phase uses a Dev/Review loop with distinct Engineer and Reviewer roles.
- [ ] ISC-LOOP-2: Phase Reviewer is cross-vendor where available, with explicit fallback/Operator-decision handling when unavailable, and is distinct from Cato.
- [ ] ISC-CATO-2: Cato exists as a dedicated artifact-auditor agent at `.github/agents/yubikit-cato.md`.
- [ ] ISC-CATO-3: Cato uses official opposite-vendor semantics, fails closed on ambiguous current vendor, and rejects same-vendor review.
- [ ] ISC-CATO-4: Repo-local Cato execution is adapted to UV/Python via `.github/tools/cato_run.py` and `.github/tools/cross_vendor_router.py`.
- [ ] ISC-CATO-5: Cato runtime artifacts are not committed, not ignored, and are reported for Operator inspection.
- [ ] ISC-COPILOT-1: Copilot workflow artifacts exist under `.github/skills/` and `.github/agents/` for the Dev Team workflow, Engineer, Reviewer, and Cato.
- [ ] ISC-LEARN-1: Each phase produces a learning document under `docs/yubikit/learnings/`.
- [ ] ISC-COMMIT-1: Successful phases are committed only according to Operator-approved commit policy after status/diff inspection, verification, review, and learning synthesis.
- [ ] ISC-FINAL-1: Final readiness synthesizes all phase learnings and the updated house-style assessment into `docs/yubikit/YUBIKIT_FINAL_READINESS_ASSESSMENT.md`.
- [x] Anti-ISC-1: The baseline audit does not perform broad code refactors or behavior changes.
- [x] Anti-ISC-2: The plan does not recommend abstraction solely because two pieces of code look similar.
- [x] Anti-ISC-3: The plan does not declare readiness based only on formatting, lints, or shallow test presence.

## Test Strategy

| ISC | Type | Check | Threshold | Tool |
|---|---|---|---|---|
| ISC-HS-1..4 | document review | Verify house style sections and concrete do/do-not rules | all present | manual/read |
| ISC-AUD-1 | repository inventory | Compare module list against `crates/yubikit` files | no missing namespace | glob/grep |
| ISC-AUD-2..4 | audit template review | Confirm every module section uses the required assessment fields | all modules complete | manual/read |
| ISC-SEC-1..5 | static review | Search secret/crypto surfaces, inspect representative flows, classify equality/clone behavior | all findings classified | grep/read |
| ISC-ERR-1 | static review | Inspect error enums and mapping helpers | all deviations recorded | grep/read |
| ISC-LOG-1 | static review | Inspect `log::` and `log_traffic!` calls | all log categories classified | grep/read |
| ISC-TST-1..2 | test review | Inspect unit, integration, example, and hardware test patterns | theatrical/inconsistent tests recorded | grep/read |
| ISC-DRY-1 | design review | Identify repeated invariants vs protocol-local duplication | every candidate classified | manual/read |
| ISC-API-1 | crate-root review | Inspect crate docs, module exports, feature gates, lint posture | all public-surface findings recorded | read/grep |
| ISC-FEAT-1 | build review | Compile supported feature combinations where environment allows | pass or documented blocker | cargo |
| ISC-TOOL-1 | tooling review | Record fmt/clippy/security tooling status and hardware-test availability | pass or documented blocker | cargo/tooling |
| ISC-FW-1 | spec review | Check firmware gates against cited sources | all gates classified | docs/code review |
| ISC-COMPAT-1 | parser/protocol review | Check protocol formats for compatibility risks | all risks recorded | read/tests |
| ISC-SCP-1 | cross-module review | Trace secure-channel state/session lifetime interactions | all interactions classified | read/tests |
| ISC-LIFE-1..2 | document review | Verify staged lifecycle exists | pass/fail | manual/read |
| ISC-CATO-1 | external review | Run Cato-style review using Anthropic Opus via Vertex where available | pass or documented skip | claude/opencode |
| ISC-OP-1..3 | operator setup review | Verify Operator Interview requirements, local context artifact, autonomy, hardware, commit, and quality-gate fields | all required fields defined | manual/read |
| ISC-LOOP-1..2 | workflow review | Verify Engineer/Reviewer loop and cross-vendor distinction from Cato | pass/fail | manual/read |
| ISC-CATO-2..5 | artifact-audit review | Verify Cato agent, UV/Python runner, opposite-vendor routing, and runtime artifact policy | pass/fail | read/python |
| ISC-COPILOT-1 | artifact review | Verify Copilot skill/agent files exist and align with the ISA | pass/fail | read |
| ISC-LEARN-1 | workflow review | Verify phase learning document requirements are defined | pass/fail | manual/read |
| ISC-COMMIT-1 | process review | Verify commit policy gates successful phases and forbids staging runtime/local artifacts by default | pass/fail | manual/read |
| ISC-FINAL-1 | workflow review | Verify final readiness synthesis is required | pass/fail | manual/read |
| Anti-ISC-1..3 | process review | Verify audit plan prevents premature refactor and shallow readiness claims | pass/fail | manual/read |

## Tooling Baseline

The baseline audit should record these commands and outcomes where the environment supports them:

```text
cargo fmt --all -- --check
cargo clippy -p yubikit --all-targets --all-features
cargo check -p yubikit --no-default-features
cargo check -p yubikit --features pcsc
cargo check -p yubikit --features hid
cargo test -p yubikit --lib
cargo test -p yubikit --tests --no-run
```

Optional security/tooling checks should be recorded if installed, but missing tools are not automatic audit failures:

```text
cargo audit
cargo deny check
cargo miri test -p yubikit --lib
```

Hardware tests require explicit operator readiness and documented environment variables. The audit must distinguish "not run because no hardware approval" from "failed" and "passed".

Record the environment used for tooling commands, especially on Windows/WSL systems where host and WSL toolchains may differ.

## Features

| Feature | Description | Satisfies | Depends On | Parallelizable |
|---|---|---|---|---|
| Establish House Style | Create and review `docs/yubikit/HOUSE_STYLE.md` as the canonical standard. | ISC-HS-1..4 | none | false |
| Establish Orchestration Workflow | Create Copilot skill/agents, UV/Python Cato runner, Operator Interview requirements, and pasteable meta prompt. | ISC-OP-1..3, ISC-LOOP-1..2, ISC-CATO-2..5, ISC-COPILOT-1, ISC-LEARN-1, ISC-COMMIT-1, ISC-FINAL-1 | Establish House Style | false |
| Inventory Yubikit | Build complete module/app/test/example inventory. | ISC-AUD-1 | Establish House Style | false |
| Baseline Module Audit | Assess every module against the house style and produce findings/remediation tasks. | ISC-AUD-2..4, ISC-SEC-1..5, ISC-ERR-1, ISC-LOG-1, ISC-TST-1..2, ISC-DRY-1, ISC-API-1, ISC-FEAT-1, ISC-TOOL-1, ISC-FW-1, ISC-COMPAT-1, ISC-SCP-1 | Inventory Yubikit | true by module |
| Cato Plan Review | Run external Cato-style review of house style and audit plan. | ISC-CATO-1 | Establish House Style, Baseline audit plan | false |
| Module Remediation | Future phase: remediate one module/namespace at a time. | ISC-LIFE-1 | Baseline Module Audit | true by module after dependency checks |
| Second-Pass Consolidation Audit | Future phase: reassess helper/core opportunities after all modules have been locally cleaned. | ISC-LIFE-2 | Module Remediation complete | false |
| Final Readiness Audit | Future phase: re-audit entire namespace and rerun Cato-pass before readiness claim. | ISC-CATO-1 | Second-Pass Consolidation Audit | false |

## Baseline Audit Template

Each module section must use this structure:

```text
### <module or namespace>

Files:
- <paths>

Responsibilities:
- <what this module owns>

Sensitive surfaces:
- <secrets, keys, tokens, PINs, APDUs, credentials, destructive operations>

House-style assessment:
- Module shape:
- API/session style:
- Error handling:
- Secret/crypto safety:
- Constant-time comparison and secret cloning:
- Protocol parsing/framing:
- Logging:
- Testing:
- DRY/consolidation:
- Documentation:
- Unsafe/lints:

Findings:
- [severity] <file:line> <issue and evidence>

Remediation plan:
- <small, executable task>

Verification:
- <commands, review probes, or hardware-test requirements>
```

## Recommended Audit Order

Audit foundational surfaces before applets that depend on them:

1. `lib`, `core`, `logging`, and `__internal`
2. `keys`, `cbor`, and `smartcard`
3. `platform`, `device`, and `management`
4. `otp` and `yubiotp`
5. `oath`, `hsmauth`, `securitydomain`, `piv`, and `openpgp`
6. `fido`, `ctap`, and `ctap2`
7. `webauthn` and WebAuthn extensions
8. examples and shared test harness
9. cross-module consolidation candidates

This order prevents downstream applet findings from being based on unreviewed assumptions about secret wrappers, core traits, logging helpers, key parsing, APDU handling, and transport behavior.

## Crypto Audit Depth

Crypto-heavy flows require end-to-end lifecycle tracing, not isolated call-site spot checks. The baseline audit must trace at least these flows from input/derivation through use and drop:

- CTAP2 PIN/UV protocol ECDH, KDF, encryption, MAC, token handling, and PIN padding
- SCP03/SCP11 key setup, session state, APDU wrapping, and teardown
- PIV management key authentication, key import/generation, signing/decryption/ECDH/KEM operations
- HSM Auth management keys, credential passwords, asymmetric credentials, and derived session keys
- OATH password/access-key derivation, shared-secret import, HOTP/TOTP calculation, and response verification
- YubiOTP slot secrets, access codes, private IDs, static password material, and challenge-response HMAC

For each flow, record secret owner, copies/clones, temporary buffers, equality checks, logs/errors/panics, and zeroization boundary.

## Theatrical Test Definition

A theatrical test is a test that creates confidence without meaningful fault-detection value. Examples include asserting that a mock returns exactly the value configured into the mock, asserting only that a function does not panic, testing `parse(serialize(x)) == x` without malformed-input or known-vector coverage, checking only that a constructor returns `Ok` without verifying initialized state, or duplicating implementation logic in the assertion.

## Module Assessment Scope And Initial Remediation Targets

These are planning targets. The baseline audit must verify, refine, or reject them with file references.

### `lib`

Files:
- `crates/yubikit/src/lib.rs`
- `crates/yubikit/Cargo.toml`

Responsibilities:
- Crate-level documentation, public module surface, feature-gated exports, crate lint posture, README/example alignment, and dependency/feature declaration for the SDK.

Initial risks and targets:
- public module exports must match intended SDK boundaries and avoid accidental stabilization of internals
- feature documentation must match actual `pcsc`/`hid` features and examples
- crate root lint posture, especially `missing_docs`, must be intentional and effective
- README and crate docs should not drift from public API or feature names
- supported feature combinations must compile or have documented blockers

Remediation posture:
- keep crate-root changes minimal; do not hide modules or change public exports without explicit compatibility analysis

### `piv`

Files:
- `crates/yubikit/src/piv.rs`
- `crates/yubikit/tests/device_tests/piv.rs`

Responsibilities:
- PIV smart card operations: PIN/PUK, management keys, certificates, key generation/import, signing, decryption, ECDH/KEM, attestation, metadata.

Initial risks and targets:
- very large module; assess whether internal sections are coherent before recommending extraction
- management key, PIN/PUK, private key import, and PQC operations require secret/crypto lifetime audit
- repeated APDU/TLV patterns may become second-pass helper candidates
- logging likely includes success chatter and security-sensitive operation boundaries
- hardware tests must distinguish destructive reset/import flows and real behavior from setup theatre

Remediation posture:
- first pass should classify and locally clean; do not split the file unless obvious low-risk extraction exists
- preserve protocol-specific logic and firmware gates

### `openpgp`

Files:
- `crates/yubikit/src/openpgp.rs`
- `crates/yubikit/tests/device_tests/openpgp.rs`

Responsibilities:
- OpenPGP card operations: PIN/admin PIN/reset code, key generation/import, signing, decryption, authentication, KDF/config/data objects, attestation.

Initial risks and targets:
- very large module with many logged state transitions
- PIN/admin PIN/reset code and key import require secret classification
- algorithm attributes and KDF setup need spec-linked rationale
- test suite should prove actual card behavior and cleanup state consistently

Remediation posture:
- review logging first; success `info!` usage may be inconsistent with library policy
- audit repeated PIN/retry/status handling against PIV and HSM Auth

### `oath`

Files:
- `crates/yubikit/src/oath.rs`
- `crates/yubikit/tests/device_tests/oath.rs`
- `crates/yubikit/examples/oath_list.rs`

Responsibilities:
- YKOATH TOTP/HOTP credential management, access-key protection, code calculation.

Initial risks and targets:
- shared secrets, access keys, PBKDF2-derived keys, HOTP counters, and TOTP challenges need lifetime classification
- SHA-1/HMAC usage should be documented as protocol-required where relevant
- tests should include protocol vectors and behavioral edge cases, not just session success

Remediation posture:
- check `OathAccessKey`, credential secret storage, and manual zeroization consistency
- compare reset/access-key test flow to other applets

### `hsmauth`

Files:
- `crates/yubikit/src/hsmauth.rs`
- `crates/yubikit/tests/device_tests/hsmauth.rs`

Responsibilities:
- YubiHSM Auth credential storage, management keys, credential passwords, symmetric/asymmetric session key calculation.

Initial risks and targets:
- default management key, credential password, derived session keys, and EC private material require deep secret audit
- length-checked `unwrap` patterns must be classified as invariant or replaced
- APDU/TLV assembly may overlap with Security Domain and PIV helper opportunities

Remediation posture:
- prioritize secret handling and error mapping before style-only cleanup

### `securitydomain`

Files:
- `crates/yubikit/src/securitydomain.rs`
- `crates/yubikit/tests/device_tests/securitydomain.rs`

Responsibilities:
- GlobalPlatform Security Domain, SCP03/SCP11 keys, certificates, allowlists, secure channel setup/reset.

Initial risks and targets:
- SCP keys, session keys, KCVs, certificates, and allowlist trust policy need cryptographic review
- shared secure-channel concepts may belong in `smartcard` or internal helpers after second pass
- destructive tests and reset assumptions need explicit markers

Remediation posture:
- avoid premature helper extraction until `smartcard` and HSM Auth/PIV patterns are also audited

### `otp` and `yubiotp`

Files:
- `crates/yubikit/src/otp.rs`
- `crates/yubikit/src/yubiotp.rs`
- `crates/yubikit/tests/device_tests/yubiotp.rs`
- `crates/yubikit/examples/otp_serial.rs`

Responsibilities:
- OTP HID framing, modhex/CRC, YubiOTP slot programming, challenge-response, HOTP/static password/static ticket configuration.

Initial risks and targets:
- OTP AES keys, private IDs, access codes, HMAC keys, and static-password material require secret classification
- HID retry/cancel behavior and CRC verification need meaningful tests
- large `yubiotp` module may contain helper candidates but should first be locally assessed

Remediation posture:
- align OTP/YubiOTP naming and test flow with FIDO HID and Management where practical

### `fido`, `ctap`, and `ctap2`

Files:
- `crates/yubikit/src/fido.rs`
- `crates/yubikit/src/ctap.rs`
- `crates/yubikit/src/ctap2/*.rs`
- `crates/yubikit/tests/device_tests/fido.rs`
- `crates/yubikit/examples/ctap2_selection.rs`
- `crates/yubikit/examples/fido_serial.rs`

Responsibilities:
- FIDO HID abstraction, CTAP over HID and smartcard/NFC, CTAP2 commands, PIN/UV protocol, credential management, large blobs, bio enrollment, authenticator config.

Initial risks and targets:
- PIN/UV tokens, ECDH shared secrets, PIN strings, large blob keys, and bio enrollment data require secret classification
- `ctap2::pin_protocol` needs key-length, RNG, KDF, MAC truncation, and raw `Vec<u8>` return review
- generic transport errors and backend downcast invariants need house-style classification
- test suite is large and must be audited for real behavioral value and consistent hardware gating

Remediation posture:
- prioritize cryptographic review of PIN protocol and token handling
- classify helper opportunities across CTAP/WebAuthn only after WebAuthn audit

### `webauthn`

Files:
- `crates/yubikit/src/webauthn/*.rs`
- `crates/yubikit/src/webauthn/extensions/*.rs`
- `crates/yubikit/src/webauthn/extensions/sign.rs`
- `crates/yubikit/examples/webauthn*.rs`
- WebAuthn portions of `crates/yubikit/tests/device_tests/fido.rs`

Responsibilities:
- High-level WebAuthn registration/authentication and extension processing.

Initial risks and targets:
- RP ID/origin/client-data binding, credential IDs, PRF outputs, credBlob/largeBlob data, PIN/UV prompts, and preview sign extension need semantic review
- examples should model safe realistic usage without turning into application code
- extension modules should share naming, parsing, and test conventions
- preview or unstable extensions such as `sign.rs` need explicit API stability and feature-gating review

Remediation posture:
- verify high-level API does not hide security-significant WebAuthn choices
- align extension test naming and flow

### `management`

Files:
- `crates/yubikit/src/management.rs`
- management portions of `crates/yubikit/tests/device_tests.rs`
- `crates/yubikit/examples/device_info.rs`
- `crates/yubikit/examples/list_devices.rs`
- `crates/yubikit/examples/reinsert.rs`

Responsibilities:
- Device info/configuration over CCID, OTP, and FIDO; capabilities, modes, flags, resets, config lock/unlock.

Initial risks and targets:
- lock codes, reset/config operations, serial/device identity, and interface enabling/disabling need careful logging and test policy
- multi-transport backend pattern should be compared with CTAP and YubiOTP
- library-level `info!` logs for configuration/reset should be reviewed

Remediation posture:
- distinguish application-like actions from SDK library behavior; keep logs conservative

### `smartcard`

Files:
- `crates/yubikit/src/smartcard.rs`
- `crates/yubikit/examples/smartcard_serial.rs`

Responsibilities:
- ISO 7816 APDU handling, AID constants, status words, smartcard connection trait/protocol, SCP secure channel.

Initial risks and targets:
- SCP key params/state, APDU logging, status-word mapping, command chaining, and secure channel initialization need deep review
- AID comments with field-tested behavior are valuable; verify they remain concise and accurate
- potential core helper home for applet-level repeated APDU invariants after second pass

Remediation posture:
- treat as foundational; changes here require high confidence and broad regression coverage

### `keys`

Files:
- `crates/yubikit/src/keys.rs`
- `crates/yubikit/tests/device_tests/arkg_p256.rs`

Responsibilities:
- Asymmetric key models and parsing/serialization for RSA, EC, Ed25519, X25519, ML-DSA, ML-KEM, PKCS#1/PKCS#8/SPKI/OID utilities.

Initial risks and targets:
- private key material must use secret wrappers consistently
- DER parsing must reject malformed inputs without panic
- OID `new_unwrap` constants should be classified as compile-time invariant
- tests should include protocol vectors and malformed input cases

Remediation posture:
- prioritize secret ownership and parser hardening before cosmetic changes

### `device`

Files:
- `crates/yubikit/src/device.rs`
- device portions of `crates/yubikit/tests/device_tests.rs`

Responsibilities:
- Device abstraction, device info reads via multiple transports, reinsert handling, product naming.

Initial risks and targets:
- serial/device identity matching and reinsert wrong-device detection are correctness-sensitive
- logs for fallback/synthesis should be useful but not noisy
- test flow should prove real behavior and skip deterministically without hardware

Remediation posture:
- align with Management multi-transport behavior where invariants match

### `platform`

Files:
- `crates/yubikit/src/platform/*.rs`

Responsibilities:
- OS transport implementations: HID FIDO, HID OTP, PC/SC, Windows SetupDI, local device enumeration.

Initial risks and targets:
- raw transport traffic logging must stay isolated to `log_traffic!`
- Windows FFI unsafe blocks need safety comment audit
- PC/SC and HID error handling should preserve source context and avoid panics
- device enumeration behavior may require platform-specific test notes

Remediation posture:
- keep platform-specific complexity local; avoid cross-platform abstraction that hides OS differences

### `cbor`

Files:
- `crates/yubikit/src/cbor.rs`

Responsibilities:
- Minimal CBOR value model and encode/decode helpers for CTAP2/WebAuthn.

Initial risks and targets:
- parser is exposed to untrusted data and must reject malformed input cleanly
- `Debug` for byte strings uses hex; verify no secret-bearing values are accidentally debugged elsewhere
- canonical ordering and edge cases need protocol-vector tests

Remediation posture:
- keep CBOR minimal; do not import a large dependency unless correctness need is concrete

### `core`

Files:
- `crates/yubikit/src/core.rs`

Responsibilities:
- Shared `Version`, `Connection`, transport enum, byte helpers, version requirements/override.

Initial risks and targets:
- version override can affect feature gates and should be documented/testable
- helper additions should be rare and justified by second-pass consolidation

Remediation posture:
- do not move helpers into `core` during first pass unless they are truly substrate-level

### `__internal`

Files:
- `crates/yubikit/src/__internal/*.rs`

Responsibilities:
- Internal TLV helpers and `SecretValue` wrapper.

Initial risks and targets:
- `SecretValue::into_inner` unsafe escape hatch needs explicit audit
- `Clone`, `PartialEq`, redaction, zeroization, and documentation must match secret-handling policy
- TLV helpers should avoid duplicate secret buffers and reject malformed inputs

Remediation posture:
- treat as security infrastructure; small changes require focused tests and review

### `logging`

Files:
- `crates/yubikit/src/logging.rs`

Responsibilities:
- Traffic log target and byte formatting helper.

Initial risks and targets:
- policy is larger than implementation; audit usage across modules
- consider whether `hex_encode` allocation is acceptable or whether a display wrapper would be cleaner only if usage justifies it

Remediation posture:
- do not expand logging helpers until call-site audit proves need

### Examples And Test Harness

Files:
- `crates/yubikit/examples/*.rs`
- `crates/yubikit/examples/example_utils.rs`
- `crates/yubikit/tests/device_tests.rs`
- `crates/yubikit/tests/device_tests/*.rs`
- `crates/yubikit/tests/device_tests/controller.rs`

Responsibilities:
- Demonstrate public API usage and verify hardware behavior.

Initial risks and targets:
- examples should be realistic, short, and not security-misleading
- shared example utilities should not normalize insecure copy-paste patterns, hidden default secrets, or unexplained hardcoded values
- hardware tests must consistently gate destructive operations and skip behavior
- shared controller/test harness code should make hardware assumptions explicit
- module test naming and setup/cleanup flow should converge
- identify theatrical tests and replace with real behavior/vector/regression tests

Remediation posture:
- improve harness consistency before adding more tests

## Audit Lifecycle

### Phase -1: Operator Interview And Workflow Setup

Before implementation, the Orchestrator interviews the Operator and records hardware availability, target serial or no-serial mode, test/development key status, destructive-test approval, user-presence/controller availability, credentials/test-state constraints, autonomy level, quality gates, and commit policy.

Persist answers to `docs/yubikit/OPERATOR_CONTEXT.local.md`. This file is local by default and must not be staged or committed unless the Operator explicitly approves.

The Orchestrator also records available harnesses in priority order: `copilot -h`, `claude -h`, `codex -h`, `opencode -h`, plus `uv --version` and `python --version`. The selected Engineer, Reviewer, and Cato routes must be recorded before Phase 0.

### Phase 1: Baseline House Style Audit

Create/approve `HOUSE_STYLE.md`, inventory modules, and produce the full per-module assessment. Do not make code changes beyond documentation unless explicitly authorized. Findings should be concrete enough for independent remediation agents.

### Phase 2: Module-By-Module Remediation

Future engineers remediate one module or namespace at a time. Each remediation PR references the relevant audit section and house-style criteria. Changes are behavior-preserving by default. Public API changes require a concrete safety, correctness, or maintainability reason.

Every implementation phase uses a Dev/Review loop. The Engineer implements the phase. The Reviewer reviews the phase diff and verification results. Cato audits written artifacts only and is not a substitute for phase diff review.

Reviewer reviews phase output including documentation diffs. Cato additionally audits written artifacts when the phase creates or materially changes claim-bearing workflow, ISA, policy, or readiness documents.

If cross-vendor review is unavailable, the Orchestrator records the failed command, stderr or reason, selected fallback, and Operator decision. Default is to pause and ask the Operator whether to retry, proceed with same-vendor advisory review clearly labeled as non-Cato analysis only, or defer the phase. Same-vendor advisory review never satisfies the cross-vendor gate. A phase with an unsatisfied Reviewer cross-vendor gate cannot be committed or marked ready unless the Operator records a phase-scoped waiver with justification, expiration/scope, and residual risk in phase learnings and final readiness.

If Cato cannot route to the opposite vendor for an artifact gate, the Orchestrator records the failed command/reason and asks the Operator whether to retry, defer the gate, or accept an explicitly labeled non-Cato advisory review. Non-Cato advisory review never satisfies a required Cato-pass. A Cato waiver must be phase-scoped, justified, and recorded in phase learnings and final readiness as residual risk; it applies only to the named phase and does not waive future Cato triggers.

If both Reviewer and Cato cross-vendor routes are unavailable, the phase is blocked/deferred by default. The Operator may approve bounded exploratory analysis notes only: non-code observations or questions recorded in the chat/final checkpoint, not repository edits, patches, architecture rewrites, or draft implementation. No code or workflow-document edits may be made and nothing may be committed while both cross-vendor gates are unavailable. When routes are restored, implementation resumes from the last reviewed state.

Dual cross-vendor outage creates a transient blocked state. It is not an autonomy level; it overrides the selected autonomy level until cross-vendor gates recover. A waiver during dual outage cannot authorize repository edits, patches, workflow-document edits, commits, or readiness claims; it can only authorize bounded exploratory analysis notes and must record scope, expiration, and residual risk.

If cross-vendor routing is indefinitely unavailable, this workflow is not executable as designed; stop and ask the Operator to adopt a separately documented replacement review policy before further remediation work proceeds.

If the workflow requires Operator input and no answer is available, stop, leave a checkpoint with the blocked decision and exact next question, and perform no further edits, hardware actions, staging, commits, or pushes.

Decision priority order is: explicit system/developer/user safety instructions; no destructive hardware without approval; no repository edits/commits during dual cross-vendor outage; no commit without required review/Cato or phase-scoped waiver where allowed; no staging/commit of protected local/runtime artifacts; then normal phase autonomy.

Repeated single-gate waivers are not normal operation. More than one cross-vendor Reviewer or Cato waiver in a phase, or the same gate waived in two consecutive phases, pauses the workflow for Operator escalation and a documented replacement/repair plan before further remediation proceeds.

After every successful Dev/Review loop, synthesize a phase learning document under `docs/yubikit/learnings/PHASE_<NN>_<NAME>.md`. The learning document records phase goal, files changed, criteria touched, decisions, reviewer findings, fixes, verification, deferred risks, lessons for future phases, and recommended next phase.

If the Operator authorizes commits, the Orchestrator may commit successful phases only after inspecting `git status`, inspecting `git diff`, verifying intended files only, running required verification, running review, and writing the phase learning document. Runtime Cato artifacts and `OPERATOR_CONTEXT.local.md` must not be staged unless explicitly approved.

Before commit, the Orchestrator inspects `git diff --cached --name-only` and aborts if local/runtime artifacts or unrelated files are staged without explicit Operator approval.

Before commit, the Orchestrator also runs `python .github/tools/check_commit_safety.py`, which rejects staged local/runtime workflow artifacts by default.

If autonomy level D or E enables autonomous commits, the Orchestrator installs the local pre-commit hook with `python .github/tools/install_commit_safety_hook.py`. If the Operator declines the hook, autonomy degrades to C: ask before every commit. Manual git commands outside the workflow are outside the workflow's guarantees.

Agents must not use `git commit --no-verify` unless the Operator explicitly authorizes it for that commit. Phase commits should be made on a feature branch or workflow branch, not directly on the protected/default branch, unless the Operator explicitly approves direct commits. Before the first phase commit, inspect `git branch --show-current` and remote tracking state.

Agents must not rewrite published/shared history, force-push, rebase shared commits, or amend pushed phase commits unless explicitly requested by the Operator for that exact operation.

Workflow commits must use CLI git commands, not library-based git mutations that bypass hooks or command visibility. In a fresh clone or new worktree, install the local pre-commit hook before any D/E autonomous commit.

If a phase modifies `.github/tools/check_commit_safety.py`, `.github/tools/install_commit_safety_hook.py`, or the hook installation path, those safety-tool changes must receive cross-vendor Reviewer review, Cato audit of the written workflow/tooling artifact, and Operator approval of the exact staged diff before commit. Until that review is complete, commit autonomy degrades to C. The commit-safety script still runs, but it is not treated as the sole safety authority for a self-modifying safety-tool phase.

After each phase, and before context handoff when a session may end, record a checkpoint in the phase learning document or final response: current phase, autonomy level, branch, staged/untracked safety-sensitive files, completed gates, pending gates, residual risks, and exact next commands. A resumed session must read the ISA, active phase learning/checkpoint, `git status`, branch, and pending Cato/review outputs before continuing, then summarize the loaded checkpoint state to the Operator before taking edit/commit actions.

Cato audits written artifacts whenever a phase changes files under `docs/yubikit/`, `.github/skills/`, `.github/agents/`, or `.github/tools/`, except local runtime artifacts and `OPERATOR_CONTEXT.local.md`.

If a later phase discovers a defect in an earlier committed phase, forward progress stops and the current phase learning document records a re-entry note. The Operator chooses whether to revert, add a corrective phase, or reopen the earlier phase. Do not amend prior commits unless explicitly requested.

### Phase 3: Second-Pass Consolidation Audit

After all modules have been remediated once, reassess the whole namespace for helper/core opportunities that were not visible before local cleanup. Expected focus: APDU helpers, retry/status mapping, constructor patterns, secret-buffer idioms, test harness abstractions, and possible `core`, `smartcard`, `__internal`, or private-helper placement.

### Phase 4: Final Readiness Audit

Reassess every module against `HOUSE_STYLE.md`, verify no consolidation regressions, confirm tests are valuable and consistent, and rerun Cato-style review before declaring readiness.

The final audit synthesizes all phase learning documents plus the updated house-style assessment into `docs/yubikit/YUBIKIT_FINAL_READINESS_ASSESSMENT.md`.

## Workflow Artifacts

Copilot skill and agents:

- `.github/skills/yubikit-dev-team-workflow/SKILL.md`
- `.github/agents/yubikit-engineer.md`
- `.github/agents/yubikit-reviewer.md`
- `.github/agents/yubikit-cato.md`

Repo-local Cato tooling:

- `.github/tools/cato_run.py`
- `.github/tools/cross_vendor_router.py`

Preferred invocation is `uv run --no-project --python 3.12 .github/tools/cato_run.py <artifact-path> --current-vendor openai|anthropic`. The `--no-project` flag avoids this repository's Python workspace dependency resolution; Python 3.12 is a standalone-runner portability tradeoff and does not change the repository's Python target.

Operator and learning artifacts:

- `docs/yubikit/OPERATOR_CONTEXT.local.md` local by default; do not commit unless explicitly approved
- `docs/yubikit/learnings/PHASE_<NN>_<NAME>.md`
- `docs/yubikit/YUBIKIT_FINAL_READINESS_ASSESSMENT.md`

Cato runtime artifacts:

- `.github/state/cato-quota.json`
- `.github/verification/cato-findings.jsonl`

Runtime Cato artifacts are left visible to the Operator. Do not stage or commit them unless explicitly requested. Do not add them to `.gitignore`.

This visibility policy is intentional. The safety backstop is `check_commit_safety.py` and the optional local pre-commit hook, not `.gitignore`.

This no-ignore policy is an explicit Operator constraint. The residual risk is accepted in exchange for visibility; compensating controls are the commit-safety script, required local pre-commit hook for autonomous commits, prohibition on `git commit --no-verify`, CLI-only git operations for workflow commits, and hook installation before any D/E autonomous commit in a fresh clone.

Warn the Operator that manual `git add .`, `git add -A`, or `git add .github/` can stage visible runtime artifacts. Before any manual commit, run `git diff --cached --name-only` and `python .github/tools/check_commit_safety.py`.

`check_commit_safety.py` exits nonzero if staged files include `docs/yubikit/OPERATOR_CONTEXT.local.md`, `.github/state/cato-quota.json`, or `.github/verification/cato-findings.jsonl`. A zero exit means only that these protected paths are not staged; it does not replace diff review, branch checks, tests, or cross-vendor gates.

If phase learnings are written or updated before commit, Cato runs after the learning document is written so the final written-artifact set is audited.

`docs/yubikit/OPERATOR_CONTEXT.local.md` is also protected by `python .github/tools/check_commit_safety.py` and must not be staged or committed without explicit Operator approval.

Hardware-dependent phases cannot receive an unqualified readiness pass when required hardware verification was unavailable. Mark them as `qualified pass: hardware not run` or `deferred: hardware verification required`, and carry the gap into phase learnings and final readiness.

## Decisions

- 2026-06-24: Canonical house style lives at repo level under `docs/yubikit/HOUSE_STYLE.md`, not inside `crates/yubikit`, so it can be used as a benchmark/reference across remediation work.
- 2026-06-24: Start with one house-style document; split `LOGGING.md`, `TESTING.md`, `SECURITY_AND_CRYPTO.md`, `CODING_STYLE.md`, `API_DESIGN.md`, or `CONTRIBUTING.md` only when sections become too large.
- 2026-06-24: First audit identifies consolidation opportunities but should not over-consolidate; second-pass audit performs the deeper helper/core review after local remediation.
- 2026-06-24: Tests are judged by behavioral value, not coverage theatre.
- 2026-06-24: Logging policy is conservative because `yubikit` is a library for security hardware, not an application CLI.

## Changelog

- conjectured: A house-style-first audit will prevent subjective, agent-shaped remediation.
  refuted by: not refuted; baseline audit and Cato-style review found the structure useful and non-blocking.
  learned: The plan needed explicit crate-root coverage, constant-time/equality criteria, audit ordering, tooling baseline, and a definition of theatrical tests before it could pass review.
  criterion now: Planning and baseline-audit criteria are complete; deep remediation criteria remain open until module-by-module work finishes.

## Verification

Planning and baseline-audit verification completed on 2026-06-24.

Artifacts:

- `docs/yubikit/HOUSE_STYLE.md`
- `docs/yubikit/YUBIKIT_HOUSE_STYLE_AUDIT_ISA.md`
- `docs/yubikit/YUBIKIT_BASELINE_HOUSE_STYLE_AUDIT.md`

Mechanical baseline recorded in `YUBIKIT_BASELINE_HOUSE_STYLE_AUDIT.md`:

```text
cargo fmt --all -- --check                         pass
cargo check -p yubikit                             pass
cargo check -p yubikit --no-default-features       pass
cargo check -p yubikit --features pcsc             pass
cargo check -p yubikit --features hid              pass
cargo clippy -p yubikit --all-targets --all-features pass with one test warning
cargo test -p yubikit --lib                        pass, 270 tests
cargo test -p yubikit --tests --no-run             pass
```

Cato-style review:

- Initial plan review returned medium concerns.
- Revisions addressed crate-root scope, constant-time/equality criteria, theatrical-test definition, audit order, tooling baseline, crypto depth, firmware/protocol compatibility, SCP/session lifetime, and shared test/example utilities.
- Re-review passed with low criticality and no blockers.
- Completed baseline audit also passed Cato-style review with low criticality and no blockers.
- Review was run with `claude --model opus --permission-mode plan`; provider/Vertex routing was not inspectable from CLI output.

Deferred criteria intentionally left unchecked:

- `ISC-SEC-1` through `ISC-SEC-5`: require module-level secret inventory and classification.
- `ISC-ERR-1`: requires module-by-module error policy remediation.
- `ISC-LOG-1`: requires logging classification and normalization.
- `ISC-TST-1` and `ISC-TST-2`: require test value classification and harness normalization.
- `ISC-DRY-1`: requires second-pass consolidation after local remediation.
- `ISC-FW-1`, `ISC-COMPAT-1`, and `ISC-SCP-1`: require deeper firmware/protocol/SCP tracing during module remediation.
