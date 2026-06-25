---
name: yubikit-dev-team-workflow
description: Phased Operator-governed Dev/Review workflow for Yubikit house-style remediation.
---

# Yubikit Dev Team Workflow

Use this skill for the staged remediation of `crates/yubikit` toward the house-style vision.

## Required Documents

Read before implementation:

- `docs/yubikit/HOUSE_STYLE.md`
- `docs/yubikit/YUBIKIT_HOUSE_STYLE_AUDIT_ISA.md`
- `docs/yubikit/YUBIKIT_BASELINE_HOUSE_STYLE_AUDIT.md`

## Phase -1: Operator Interview

Do not start code work until the Operator Interview is complete.

Explain that this is a phased remediation program for a security-sensitive Rust SDK. Each phase has an Engineer implementation pass and a cross-vendor Reviewer pass. Cato audits written artifacts. Hardware tests may be destructive or require user presence.

Ask and record:

- YubiKey availability
- target `YUBIKEY_SERIAL` or `YUBIKEY_NO_SERIAL=1`
- whether the key is a dedicated test/development or allow-listed key
- destructive SDK test approval
- applet reset, slot overwrite, PIN/PUK, management-key, credential deletion, and persistent-state approval
- user-presence availability
- `CONTROLLER=interactive` or Pico controller URL/`PICO_PORT`
- credential/test-state constraints
- autonomy level
- quality gates
- commit policy

Persist answers to:

```text
docs/yubikit/OPERATOR_CONTEXT.local.md
```

This file is local by default. Do not stage or commit it unless the Operator explicitly approves.

## Autonomy Levels

- `B`: code edits allowed, no commits.
- `C`: code edits allowed, ask before every commit.
- `D`: code edits and commits allowed after a successful Dev/Review phase.
- `E`: full local autonomy except destructive hardware tests and public API changes require approval.

There is no read-only/docs-only autonomy level in this workflow; implementation work is expected over the full program. Individual phases may still be documentation-heavy or hygiene-only, but the Operator is authorizing an implementation workflow rather than a passive audit.

The Operator may still impose a per-phase read-only scoping gate before granting edits for that phase. This is a quality gate, not a global autonomy level.

## Tool Discovery

Check likely Operator harnesses in this order:

```text
copilot -h
claude -h
codex -h
opencode -h
```

Also check:

```text
uv --version
python --version
```

Record availability and selected Engineer/Reviewer/Cato routes in `OPERATOR_CONTEXT.local.md`.

## Roles

- Engineer: implementation agent; use `.github/agents/yubikit-engineer.md`.
- Reviewer: cross-vendor phase implementation reviewer; use `.github/agents/yubikit-reviewer.md`.
- Cato: cross-vendor artifact auditor; use `.github/agents/yubikit-cato.md`.

Reviewer is not Cato. Reviewer reviews phase diffs. Cato audits written artifacts.

## Cross-Vendor Rule

- If Engineer is GPT-5.5/OpenAI, Reviewer should be Anthropic Opus 4.8 where available.
- If Engineer is Opus 4.8/Anthropic, Reviewer should be GPT-5.5 where available.
- Same-vendor review is invalid unless no cross-vendor route exists; document any infrastructure skip.
- Cato must fail closed if current/authoring vendor is ambiguous.

If cross-vendor review is unavailable, the Orchestrator must record the failed command, stderr or reason, selected fallback, and Operator decision. Default is to pause and ask the Operator whether to retry, proceed with same-vendor advisory review clearly labeled as non-Cato analysis only, or defer the phase. Same-vendor advisory review never satisfies the cross-vendor gate. A phase with an unsatisfied Reviewer cross-vendor gate cannot be committed or marked ready unless the Operator records a phase-scoped waiver with justification, expiration/scope, and residual risk in phase learnings and final readiness.

If Cato cannot route to the opposite vendor for an artifact gate, the Orchestrator records the failed command/reason and asks the Operator whether to retry, defer the gate, or accept an explicitly labeled non-Cato advisory review. Non-Cato advisory review never satisfies a required Cato-pass. A Cato waiver must be phase-scoped, justified, and recorded in phase learnings and final readiness as residual risk; it applies only to the named phase and does not waive future Cato triggers.

If both Reviewer and Cato cross-vendor routes are unavailable, the phase is blocked/deferred by default. The Operator may approve bounded exploratory analysis notes only: non-code observations or questions recorded in the chat/final checkpoint, not repository edits, patches, architecture rewrites, or draft implementation. No code or workflow-document edits may be made and nothing may be committed while both cross-vendor gates are unavailable. When routes are restored, implementation resumes from the last reviewed state.

Dual cross-vendor outage creates a transient blocked state. It is not an autonomy level; it overrides the selected autonomy level until cross-vendor gates recover. A waiver during dual outage cannot authorize repository edits, patches, workflow-document edits, commits, or readiness claims; it can only authorize bounded exploratory analysis notes and must record scope, expiration, and residual risk.

If cross-vendor routing is indefinitely unavailable, this workflow is not executable as designed; stop and ask the Operator to adopt a separately documented replacement review policy before further remediation work proceeds.

If the workflow requires Operator input and no answer is available, stop, leave a checkpoint with the blocked decision and exact next question, and perform no further edits, hardware actions, staging, commits, or pushes.

Decision priority order is: explicit system/developer/user safety instructions; no destructive hardware without approval; no repository edits/commits during dual cross-vendor outage; no commit without required review/Cato or phase-scoped waiver where allowed; no staging/commit of protected local/runtime artifacts; then normal phase autonomy.

Repeated single-gate waivers are not normal operation. More than one cross-vendor Reviewer or Cato waiver in a phase, or the same gate waived in two consecutive phases, pauses the workflow for Operator escalation and a documented replacement/repair plan before further remediation proceeds.

## Per-Phase Dev/Review Loop

1. Engineer reads relevant docs and prior learning docs.
2. Engineer states phase goal and checklist.
3. Engineer implements only the current phase.
4. Engineer runs verification.
5. Engineer prepares a review packet.
6. Reviewer returns critical/warning/info findings.
7. Engineer fixes critical findings.
8. Engineer fixes or justifies warnings.
9. Engineer reruns verification.
10. Orchestrator writes a phase learning document.
11. Orchestrator inspects `git status` and `git diff`.
12. Orchestrator commits only if the Operator policy permits it.

Reviewer reviews phase output including documentation diffs. Cato additionally audits written artifacts when the phase creates or materially changes claim-bearing workflow, ISA, policy, or readiness documents.

## Phase Learning Documents

After every Dev/Review loop, write:

```text
docs/yubikit/learnings/PHASE_<NN>_<NAME>.md
```

Include:

- phase goal
- files changed
- house-style criteria touched
- key decisions
- reviewer findings
- fixes made
- verification run
- deferred risks
- lessons for future phases
- recommended next phase

## Commit Policy

After each successful phase:

- inspect `git status`
- inspect `git diff`
- verify only intended files changed
- run required verification
- run cross-vendor review
- synthesize phase learning doc
- commit only if the Operator pre-authorized commits or explicitly approves
- inspect `git diff --cached --name-only` before commit and abort if local/runtime artifacts are staged without explicit Operator approval
- run `python .github/tools/check_commit_safety.py` before commit; it rejects staged local/runtime workflow artifacts by default

If autonomy level D or E enables autonomous commits, install the local pre-commit hook with `python .github/tools/install_commit_safety_hook.py`. If the Operator declines the hook, autonomy degrades to C: ask before every commit. Manual git commands outside the workflow are outside the workflow's guarantees.

Cato audits written artifacts whenever a phase changes files under `docs/yubikit/`, `.github/skills/`, `.github/agents/`, or `.github/tools/`, except local runtime artifacts and `OPERATOR_CONTEXT.local.md`.

Use one concise commit per phase unless the Operator requests otherwise. Never stage `OPERATOR_CONTEXT.local.md`, Cato runtime files, or unrelated worktree changes unless explicitly approved.

Agents must not use `git commit --no-verify` unless the Operator explicitly authorizes it for that commit. Phase commits should be made on a feature branch or workflow branch, not directly on the protected/default branch, unless the Operator explicitly approves direct commits. Before the first phase commit, inspect `git branch --show-current` and remote tracking state.

Agents must not rewrite published/shared history, force-push, rebase shared commits, or amend pushed phase commits unless explicitly requested by the Operator for that exact operation.

Workflow commits must use CLI git commands, not library-based git mutations that bypass hooks or command visibility. In a fresh clone or new worktree, install the local pre-commit hook before any D/E autonomous commit.

If a phase modifies `.github/tools/check_commit_safety.py`, `.github/tools/install_commit_safety_hook.py`, or the hook installation path, those safety-tool changes must receive cross-vendor Reviewer review, Cato audit of the written workflow/tooling artifact, and Operator approval of the exact staged diff before commit. Until that review is complete, commit autonomy degrades to C. The commit-safety script still runs, but it is not treated as the sole safety authority for a self-modifying safety-tool phase.

After each phase, and before context handoff when a session may end, record a checkpoint in the phase learning document or final response: current phase, autonomy level, branch, staged/untracked safety-sensitive files, completed gates, pending gates, residual risks, and exact next commands. A resumed session must read the ISA, active phase learning/checkpoint, `git status`, branch, and pending Cato/review outputs before continuing, then summarize the loaded checkpoint state to the Operator before taking edit/commit actions.

## Runtime Cato Artifacts

The UV/Python Cato runner may write:

```text
.github/state/cato-quota.json
.github/verification/cato-findings.jsonl
```

Do not stage or commit these unless the Operator explicitly requests it. Do not add them to `.gitignore`; leave them visible for Operator inspection.

`docs/yubikit/OPERATOR_CONTEXT.local.md` is also protected by `python .github/tools/check_commit_safety.py` and must not be staged or committed without explicit Operator approval.

The workflow intentionally leaves local/runtime artifacts visible instead of adding them to `.gitignore`, per Operator policy. The safety backstop is the commit-safety script and optional local pre-commit hook, not ignore-based hiding.

This no-ignore policy is an explicit Operator constraint. The residual risk is accepted in exchange for visibility; compensating controls are the commit-safety script, required local pre-commit hook for autonomous commits, prohibition on `git commit --no-verify`, CLI-only git operations for workflow commits, and hook installation before any D/E autonomous commit in a fresh clone.

Warn the Operator that manual `git add .`, `git add -A`, or `git add .github/` can stage visible runtime artifacts. Before any manual commit, run `git diff --cached --name-only` and `python .github/tools/check_commit_safety.py`.

`check_commit_safety.py` exits nonzero if staged files include `docs/yubikit/OPERATOR_CONTEXT.local.md`, `.github/state/cato-quota.json`, or `.github/verification/cato-findings.jsonl`. A zero exit means only that these protected paths are not staged; it does not replace diff review, branch checks, tests, or cross-vendor gates.

If phase learnings are written or updated before commit, Cato runs after the learning document is written so the final written-artifact set is audited.

## Rollback And Re-Entry

If a later phase discovers a defect in an earlier committed phase, stop forward progress and create a re-entry note in the current phase learning document. The Operator chooses whether to revert, add a corrective phase, or reopen the earlier phase. Do not amend prior commits unless explicitly requested.

## Hardware Test Policy

Hardware tests are never assumed available; they depend on Operator Interview answers.

If no YubiKey is present, skip hardware execution and record `not run: no hardware available`.

Hardware-dependent phases cannot receive an unqualified readiness pass when required hardware verification was unavailable. Mark them as `qualified pass: hardware not run` or `deferred: hardware verification required`, and carry the hardware gap into the phase learning document and final readiness assessment.

If a YubiKey is present and allow-listed/test-designated, destructive SDK tests may run only if the Operator confirms destructive approval.

If the Operator is not available for touch/user-presence and no controller is configured, skip FIDO/WebAuthn user-presence tests and record `not run: no user presence/controller available`.

Never run reset, reconfigure, overwrite, delete, PIN/PUK, or management-key-changing operations without Operator-approved test-key/destructive scope.

## Phase Order

### Phase 0: Baseline Hygiene

- Fix README feature drift: README references `hardware`, but actual `yubikit` features are `pcsc` and `hid`.
- Fix clippy warning in `crates/yubikit/src/webauthn/extensions/sign.rs:590`.
- No behavior changes.

### Phase 1: Secret Inventory

Create:

```text
docs/yubikit/SECRET_INVENTORY.md
```

Audit `SecretValue`, `Zeroizing`, `ZeroizeOnDrop`, manual `Drop`, secret-bearing `Clone`, secret-bearing `PartialEq`, secret-bearing `Debug`/`Display`, logs/errors/panics near secrets, and raw `Vec<u8>` values that may hold secret or secret-adjacent material.

### Phase 2: Foundational Modules

- `lib`
- `core`
- `logging`
- `__internal`
- `keys`
- `cbor`
- `smartcard`

### Phase 3: Transport And Device Modules

- `platform`
- `device`
- `management`

### Phase 4: Medium Applet Pilot

Choose `hsmauth` or `oath`. Do not start with `piv`, `openpgp`, or `webauthn`.

### Phase 5: Remaining Applets

- `securitydomain`
- `otp` / `yubiotp`
- `fido` / `ctap` / `ctap2`
- `webauthn`
- `piv`
- `openpgp`

### Phase 6: Second-Pass Consolidation Audit

Only after all modules are locally remediated. Look for APDU helpers, retry/status-word mapping, session constructor helpers, secret-buffer idioms, test harness abstractions, and possible placement in `core`, `smartcard`, `__internal`, or private helpers.

### Phase 7: Final Readiness Audit

Re-audit all of `crates/yubikit` against `HOUSE_STYLE.md`, then synthesize all learnings into:

```text
docs/yubikit/YUBIKIT_FINAL_READINESS_ASSESSMENT.md
```

## Verification Commands

Run as applicable:

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

Optional if available:

```text
cargo audit
cargo deny check
cargo miri test -p yubikit --lib
```
