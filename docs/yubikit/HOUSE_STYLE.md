# Yubikit House Style

This document defines the house style for `crates/yubikit`. It is the canonical reference for future audits, remediation work, and code review in the Rust SDK.

The target persona is a senior Rust/C systems engineer writing security-sensitive SDK code: terse, explicit, spec-aware, boring in the best way, and allergic to unnecessary abstraction. The code should look as though one careful maintainer wrote it, even when agents assist.

## Purpose

`yubikit` is a hardware security SDK. Its style must make protocol behavior, secret handling, and failure modes easy to review. Consistency is not cosmetic here; it reduces audit cost and prevents subtle security regressions.

This document is authoritative for `crates/yubikit`. If a module has a strong protocol-specific reason to differ, document the reason locally and prefer preserving correctness over forced uniformity.

## Principles

- Prefer less code when less code is equally clear and safe.
- Make protocol invariants visible at the boundary where they matter.
- Keep abstractions small, local, and justified by repeated invariants, not superficial similarity.
- Preserve applet-specific semantics; do not flatten different protocols into one leaky abstraction.
- Avoid cleverness. A reviewer should be able to predict the next line.
- Treat logs, errors, docs, and tests as API-adjacent surfaces.
- Make security posture mechanical where possible: types, wrappers, lints, tests, and review checklists.

## Module Shape

Preferred module order:

1. license header
2. module-level `//!` documentation
3. imports
4. protocol constants and small type aliases
5. errors
6. public value types
7. secret wrapper types
8. session/backend types
9. constructors
10. public operations
11. private helpers
12. tests

Use section separators sparingly for large modules where they improve scanning. Do not add decorative structure to small files.

Module docs should explain the applet/protocol role, the main entry point, and important safety or destructive-operation caveats. Examples should be short and realistic.

## API Design

Public APIs should be explicit about ownership, mutability, and protocol state.

Do:
- return typed public results when the SDK knows the meaning of the data
- return opaque byte buffers only when the protocol surface is inherently opaque
- name raw opaque values as `*_bytes`, `credential_id`, `apdu`, `cbor`, or similarly precise terms
- preserve recoverable connections on failed session construction where callers can reasonably continue
- use `#[non_exhaustive]` for public enums that may grow with firmware or standards
- keep builder/config types boring and inspectable

Do not:
- expose secret-bearing `Vec<u8>` without a wrapper or explicit documentation
- add generic helper traits unless at least two modules share the same invariant and the helper removes risk or code volume
- hide protocol state transitions behind surprising constructors
- make public API changes for style only unless the existing API is unsafe or materially misleading

## Error Handling

Errors should preserve protocol meaning and support diagnosis without leaking secrets.

Preferred style:
- applet-level public errors use `thiserror`
- public applet error enums are normally `#[non_exhaustive]`
- applet errors use consistent categories: unsupported feature, invalid input/data, invalid state, PIN/auth failure, transport/connection failure
- transport/protocol errors preserve the source error where useful
- status-word mapping is centralized or made obviously consistent across applets
- PIN retry errors consistently expose remaining retries when the device provides that information

Allowed but scrutinized:
- `String` payloads for detailed invalid-response context
- generic transport errors where the session is intentionally transport-generic
- `expect` for impossible invariants, provided the message states that it is an internal bug

Do not:
- collapse device-authentication failures into generic invalid data
- include PINs, keys, tokens, challenges, decrypted plaintext, or raw secret-bearing buffers in error messages
- use `unwrap` in production parsing of device-controlled data
- return ambiguous errors when firmware version, unsupported applet, invalid input, and malformed response can be distinguished

## Lints And Mechanical Checks

The current workspace lint baseline allows some practical complexity, including `clippy::too_many_arguments` and `clippy::type_complexity`. Do not treat those allowances as permission to add avoidable complexity.

Required audit checks:
- `#![warn(missing_docs)]` at the crate root remains intentional and effective
- feature combinations compile where supported: default features, `--no-default-features`, `--features pcsc`, and `--features hid`
- `cargo clippy` findings are classified before readiness claims
- `unwrap`, `expect`, `allow`, and `unsafe` occurrences in production code are justified locally or remediated
- secret-bearing `Clone`, `Debug`, `Display`, and `PartialEq` implementations are reviewed explicitly

Potential future lints such as `clippy::unwrap_used` or stricter unsafe lints should be considered only after the baseline audit classifies existing occurrences. Do not add lints that create broad churn before module-local remediation is understood.

## Session Construction

Applet sessions should follow one of two clear patterns.

For single-transport smart card applets:
- constructor creates protocol/backend
- constructor selects the applet AID
- constructor performs mandatory version/probe steps
- constructor initializes SCP only where requested and in a documented order
- on initialization failure, constructor returns `(error, connection)` when the connection can be recovered

For multi-transport applets:
- backend selection is explicit (`new`, `new_fido`, `new_otp`, `new_with_scp`, etc.)
- backend trait objects are private implementation details unless public abstraction is required
- downcast-based `into_connection` paths must have invariant `expect` messages that identify internal SDK bugs

The constructor shape should be predictable across PIV, OpenPGP, OATH, HSM Auth, Security Domain, Management, YubiOTP, CTAP, and WebAuthn.

## Secret Handling

Secret material must have an obvious owner and lifetime.

Use one of these patterns:
- `SecretValue<T>` for owned secret values that need redacted `Debug` and `Display`
- `Zeroizing<T>` for temporary buffers and derived material
- `ZeroizeOnDrop` or manual `Drop` when a type cannot use `Zeroizing`
- borrowed slices for short-lived protocol assembly, provided the owner is already protected

Required behavior:
- secret wrappers redact `Debug` and `Display`
- secret-bearing temporary buffers are zeroized on drop
- cloneable secret types are intentional and reviewed
- secret escape hatches such as `into_inner` are rare, documented, and locally justified
- constant-time comparison is used for adversarial secret comparisons
- non-constant-time `PartialEq` on secret wrappers is allowed only for explicitly non-security-critical comparisons

Every `PartialEq` implementation or derived equality on a secret-bearing type must be classified during audit as constant-time, non-adversarial, or incorrect. Every `Clone` implementation or derive on a secret-bearing type must be classified as protocol/API-required, convenience-only, or incorrect.

Do not:
- log secrets or secret-derived protocol material
- place secrets in panic messages or error strings
- use plain `Vec<u8>` fields for private keys, PINs, passwords, access keys, management keys, session keys, PIN/UV tokens, or shared secrets
- duplicate secret material merely for convenience

## Cryptography

Do not invent cryptography. Implement protocol-required composition using established crates and keep the protocol citation close to surprising choices.

Required review points:
- key lengths are checked before slicing
- IV, nonce, and RNG behavior follows the relevant spec
- KDF labels, salts, and output lengths are explicit
- MAC truncation is documented when protocol-required
- legacy algorithms such as SHA-1, 3DES, or CBC are marked as protocol-required, not recommended design choices
- public keys, credential identifiers, signatures, ciphertexts, tokens, and secrets are classified correctly
- firmware/version gates protect algorithms and commands that are not universally supported

RNG failures must be handled deliberately. `expect("getrandom failed")` is acceptable only if the surrounding API cannot reasonably return an error and the panic is an explicit process-level failure choice.

## APDU, HID, CBOR, And TLV Code

Protocol code should be length-first, spec-first, and defensive.

Do:
- check lengths before indexing or slicing
- name instruction, tag, parameter, and status constants
- centralize repeated framing and status-word mapping when the invariant is the same
- keep applet-specific command semantics local
- parse untrusted device data without panics
- add short comments for non-obvious protocol workarounds or field-tested deviations

Do not:
- abstract APDU/HID/CBOR/TLV helpers until at least two call sites share the same invariant
- mix raw transport logging with semantic operation logging
- let parser tests only cover happy paths

## Logging

Logging is part of the security surface. A library should diagnose, not narrate.

Levels:
- `traffic::` trace target via `log_traffic!`: raw APDU/HID traffic only
- `debug!`: operation boundaries and recoverable diagnostic context useful to SDK maintainers
- `info!`: rare; only approved user-visible or security-relevant state transitions, and only if the SDK policy explicitly wants library-level success logs
- `warn!`: abnormal condition that the SDK recovers from and that callers may need to know about
- `error!`: only when the SDK swallows an error instead of returning it; this should be rare

Rules:
- no PINs, passwords, management keys, access keys, private keys, shared secrets, PIN/UV tokens, decrypted plaintext, challenges, responses, or secret-bearing buffers in logs
- raw protocol bytes appear only through `log_traffic!`
- semantic logs should use stable wording across applets
- success logs such as "credential deleted" or "PIN changed" require review; returning `Ok(())` is usually enough for a library
- logs must not be needed to understand normal control flow

Review existing `info!` calls aggressively. The default position for a security SDK is quieter than an application CLI.

## Testing

Tests must prove real behavior. Tests that cannot fail for the right reason are theatre and should not be added.

A theatrical test is a test that gives confidence without meaningful fault-detection value. Examples include asserting that a mock returns exactly the value configured into the mock, asserting only that a function does not panic, testing `parse(serialize(x)) == x` without malformed-input or known-vector coverage, checking only that a constructor returns `Ok` without verifying initialized state, or duplicating implementation logic in the assertion.

Valuable tests cover:
- externally observable SDK behavior
- protocol vectors and captured device responses
- malformed input rejection
- length boundaries
- error mapping
- firmware/version gates
- secret redaction and zeroization behavior where practical
- destructive-operation guardrails
- cross-transport behavior where the public API promises it

Preferred test flow:

```text
arrange: create/reset/select applet or load a protocol vector
act: perform one operation
assert: verify public result, device state, error, or emitted bytes
cleanup: restore state if hardware/destructive
```

Naming:
- use behavior-first names such as `rejects_pin_shorter_than_four_bytes`
- avoid vague names such as `test_new`, `test_parse`, `works`, or `test_error`

Pure tests:
- should be deterministic and not require hardware
- should test parsers, encoders, crypto composition, error mapping, and edge cases
- should not only assert that a mock returns the value configured into the mock

Hardware tests:
- must be clearly gated by environment variables
- must distinguish destructive and non-destructive tests
- must use consistent skip messages, setup helpers, and cleanup flow across applets
- must not depend on hidden ordering or a developer's personal YubiKey state
- should document firmware, transport, and reset assumptions

Cross-module test style should be consistent in abstraction, naming, and flow. If one applet has a clean setup/skip/destructive marker pattern, other applets should converge on it unless protocol requirements differ.

Shared test and example utilities are part of the audited surface. They must not normalize insecure copy-paste patterns, hardcoded secrets outside clearly marked test contexts, or hidden device-state assumptions.

## Documentation

Documentation should help a maintainer use the SDK correctly and review protocol choices.

Do:
- document public APIs because the crate warns on missing docs
- explain destructive operations and security-sensitive defaults
- include spec references for surprising constants or behavior
- keep examples short, compilable where practical, and realistic

Do not:
- add comments that merely restate Rust syntax
- use marketing language
- hide security caveats in examples
- document behavior the code does not enforce

## Unsafe Code

Unsafe code is allowed only where necessary for FFI, layout, or carefully audited ownership transfer.

Rules:
- every unsafe block has a nearby safety comment explaining the invariant
- platform FFI unsafe remains isolated in platform modules
- secret extraction unsafe is treated as a high-scrutiny exception
- no protocol parsing logic is hidden inside unsafe blocks
- unsafe code receives explicit audit coverage before readiness is claimed

## Dependencies

Prefer established crates already present in the workspace. New dependencies need a concrete reason: security, correctness, maintenance reduction, or standards support.

Do not add dependencies to avoid writing a small obvious helper. Do not duplicate cryptographic primitives already provided by reviewed crates.

## Consolidation Policy

The first pass should make each module locally clean. The second pass should look for cross-module consolidation once local intent is clear.

Extract helpers only when they:
- encode the same invariant in multiple places
- reduce code volume without hiding protocol semantics
- lower security risk
- improve testability or error consistency

Good candidates may include APDU framing, PIN retry extraction, status-word mapping, session constructor scaffolding, redacted secret wrappers, hardware test setup, and protocol-vector test helpers.

Bad candidates include generic applet super-traits, protocol-flattening abstractions, and helpers that obscure which spec command is being executed.

## Review Checklist

Before approving a `yubikit` change, ask:

- Does this preserve protocol semantics?
- Is secret ownership obvious?
- Are errors precise without leaking sensitive data?
- Are logs quiet, safe, and useful?
- Could this code be shorter without losing clarity?
- Is any abstraction justified by a repeated invariant?
- Would a hardware SDK maintainer trust these tests?
- Does the module still look like the rest of `yubikit`?
- Is every `unwrap`, `expect`, `allow`, and `unsafe` justified?

## Future Subdocuments

This document is intentionally the initial single source of truth. Split sections into `docs/yubikit/LOGGING.md`, `TESTING.md`, `SECURITY_AND_CRYPTO.md`, `CODING_STYLE.md`, `API_DESIGN.md`, or `CONTRIBUTING.md` only when the section becomes too large for this document.
