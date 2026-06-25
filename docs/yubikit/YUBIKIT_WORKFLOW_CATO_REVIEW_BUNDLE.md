# Yubikit Workflow Cato Review Bundle

This artifact bundles the claims that should be audited before approving the Yubikit remediation workflow.

Cato instruction: audit this artifact as the written artifact under review. Do not inspect or request tools for the referenced files. Treat the artifact list as context for claims, not as a request to read those files.

## Artifact Set

- `docs/yubikit/HOUSE_STYLE.md`: canonical house style for `crates/yubikit`.
- `docs/yubikit/YUBIKIT_HOUSE_STYLE_AUDIT_ISA.md`: ISA/PRD for the audit and remediation lifecycle.
- `docs/yubikit/YUBIKIT_BASELINE_HOUSE_STYLE_AUDIT.md`: baseline findings and prioritized remediation backlog.
- `docs/yubikit/YUBIKIT_ORCHESTRATOR_META_PROMPT.md`: pasteable prompt for the Operator to start the workflow.
- `.github/skills/yubikit-dev-team-workflow/SKILL.md`: Copilot skill describing the operational workflow.
- `.github/agents/yubikit-engineer.md`: implementation agent role.
- `.github/agents/yubikit-reviewer.md`: phase diff/review agent role.
- `.github/agents/yubikit-cato.md`: artifact-audit agent role.
- `.github/tools/cato_run.py`: UV/Python Cato runner.
- `.github/tools/cross_vendor_router.py`: opposite-vendor route resolver.
- `.github/tools/check_commit_safety.py`: staged-file safety checker for local/runtime artifacts.
- `.github/tools/install_commit_safety_hook.py`: local pre-commit hook installer for commit-safety checks.

## Core Claims To Audit

1. The workflow begins with Phase -1, an Operator Interview, before implementation.
2. Operator answers are saved to `docs/yubikit/OPERATOR_CONTEXT.local.md`, which is local by default, protected by `python .github/tools/check_commit_safety.py`, and not committed unless explicitly approved.
3. Autonomy levels are B/C/D/E only; there is no global read-only/docs-only autonomy level because the full program is an implementation workflow. Definitions: B = edits allowed/no commits, C = edits allowed/ask before every commit, D = edits and commits allowed after successful Dev/Review phase, E = full local autonomy except destructive hardware tests and public API changes require approval. Individual phases may still be documentation-heavy or hygiene-only, and the Operator may impose a per-phase read-only scoping gate before granting edits for that phase.
4. Hardware tests are gated by Operator answers about test/development key status, destructive-test approval, user presence, and controller availability.
5. The test harness already uses `YUBIKEY_SERIAL`, `YUBIKEY_NO_SERIAL`, `CONTROLLER=interactive`, optional Pico controller URLs, `PICO_PORT`, and `TOUCH`; the workflow asks about these explicitly.
6. Every implementation phase uses a Dev/Review loop: Engineer implements, Reviewer reviews phase diff and verification results.
7. Reviewer is not Cato. Reviewer reviews implementation work; Cato audits written artifacts.
8. Cross-vendor review is required where available. If Engineer is OpenAI/GPT-5.5, Reviewer should be Anthropic Opus 4.8. If Engineer is Anthropic/Opus, Reviewer should be OpenAI/GPT-5.5. If cross-vendor review is unavailable, the Orchestrator records the failed command/reason and asks the Operator whether to retry, proceed with same-vendor advisory review clearly labeled as non-Cato analysis only, or defer; same-vendor advisory review never satisfies the cross-vendor gate. A phase with an unsatisfied Reviewer cross-vendor gate cannot be committed or marked ready unless the Operator records a phase-scoped waiver with justification, expiration/scope, and residual risk in phase learnings and final readiness.
9. Cato follows official Cato semantics: artifact-only, opposite-vendor, same-vendor invalid, ambiguous current vendor fails closed, pass/concerns/fail JSON output.
10. If Cato cannot route to the opposite vendor for an artifact gate, the Orchestrator records the failed command/reason and asks the Operator whether to retry, defer the gate, or accept an explicitly labeled non-Cato advisory review. Non-Cato advisory review never satisfies a required Cato-pass. A Cato waiver must be phase-scoped, justified, and recorded in phase learnings and final readiness as residual risk; it applies only to the named phase and does not waive future Cato triggers.
11. If both Reviewer and Cato cross-vendor routes are unavailable, the phase is blocked/deferred by default. The Operator may approve bounded exploratory analysis notes only: non-code observations or questions recorded in the chat/final checkpoint, not repository edits, patches, architecture rewrites, or draft implementation. No code or workflow-document edits may be made and nothing may be committed while both cross-vendor gates are unavailable. When routes are restored, implementation resumes from the last reviewed state.
12. The repo adapts official Cato to a lightweight Python/UV runner with no third-party Python dependencies.
13. The preferred Cato command template is `uv run --no-project --python 3.12 .github/tools/cato_run.py <artifact-path> --current-vendor <openai|anthropic>`. The `--current-vendor` value must match the artifact's last substantive authoring model family. If authorship is mixed or manually edited and ambiguous, fail closed and ask the Operator for `--current-vendor openai|anthropic`. This current review uses `--current-vendor openai` because the artifact was authored in a GPT-5.5/OpenAI session. The `--no-project` and Python 3.12 choices avoid this repo's Python workspace dependency resolution and are a documented standalone-tool portability tradeoff, not a change to the repository's Python target.
14. Plain `python .github/tools/cato_run.py ...` is the fallback.
15. Harness discovery order is `copilot -h`, `claude -h`, `codex -h`, `opencode -h`, then runtime checks for `uv --version` and `python --version`.
16. Runtime Cato artifacts are `.github/state/cato-quota.json` and `.github/verification/cato-findings.jsonl`.
17. Runtime Cato artifacts are not committed, not ignored, and left visible in `git status` for Operator inspection. This visibility policy is an explicit Operator constraint. The residual risk is accepted in exchange for visibility; compensating controls are `check_commit_safety.py`, the required local pre-commit hook for autonomous commits, a prohibition on `git commit --no-verify`, CLI-only git operations for workflow commits, and hook installation before any D/E autonomous commit in a fresh clone.
18. Operator-facing instructions must warn that manual `git add .`, `git add -A`, or `git add .github/` can stage visible runtime artifacts; before any manual commit, run `git diff --cached --name-only` and `python .github/tools/check_commit_safety.py`.
19. `check_commit_safety.py` exits nonzero if staged files include `docs/yubikit/OPERATOR_CONTEXT.local.md`, `.github/state/cato-quota.json`, or `.github/verification/cato-findings.jsonl`. A zero exit means only that these protected paths are not staged; it does not replace diff review, branch checks, tests, or cross-vendor gates.
20. After every Dev/Review loop, the Orchestrator writes a phase learning document under `docs/yubikit/learnings/PHASE_<NN>_<NAME>.md`.
21. Successful phases may be committed only according to Operator-approved commit policy, after status/diff inspection, verification, review, Cato when triggered, and learning synthesis. Before commit, `git diff --cached --name-only` must be inspected and `python .github/tools/check_commit_safety.py` must pass; the commit must abort if local/runtime artifacts or unrelated files are staged without explicit Operator approval. If autonomy level D or E enables autonomous commits, the local pre-commit hook installed by `python .github/tools/install_commit_safety_hook.py` is required. If the Operator declines the hook, autonomy degrades to C: ask before every commit. Agents must not use `git commit --no-verify` unless the Operator explicitly authorizes it for that commit. Agents must not rewrite published/shared history, force-push, rebase shared commits, or amend pushed phase commits unless explicitly requested by the Operator for that exact operation.
22. Phase commits should be made on a feature branch or workflow branch, not directly on the protected/default branch, unless the Operator explicitly approves direct commits. Before the first phase commit, inspect `git branch --show-current` and remote tracking state.
23. If a phase modifies `.github/tools/check_commit_safety.py`, `.github/tools/install_commit_safety_hook.py`, or the hook installation path, those safety-tool changes must receive cross-vendor Reviewer review, Cato audit of the written workflow/tooling artifact, and Operator approval of the exact staged diff before commit. Until that review is complete, commit autonomy degrades to C. The commit-safety script still runs, but it is not treated as the sole safety authority for a self-modifying safety-tool phase.
24. If a later phase discovers a defect in an earlier committed phase, the workflow stops forward progress and asks the Operator whether to revert, add a corrective phase, or reopen the earlier phase; prior commits are not amended unless explicitly requested.
25. The phase order is: Phase 0 baseline hygiene, Phase 1 secret inventory, Phase 2 foundational modules, Phase 3 transport/device, Phase 4 medium applet pilot, Phase 5 remaining applets, Phase 6 second-pass consolidation, Phase 7 final readiness audit.
26. Phase 0 is intentionally tiny: fix README feature drift and one clippy warning, with no behavior changes.
27. Phase 1 secret inventory is a gate for secret-adjacent module readiness.
28. Second-pass consolidation happens only after module-local remediation, to avoid premature abstraction.
29. After each phase, and before context handoff when a session may end, the Orchestrator records a checkpoint in the phase learning document or final response: current phase, autonomy level, branch, staged/untracked safety-sensitive files, completed gates, pending gates, residual risks, and exact next commands. A resumed session must read the ISA, active phase learning/checkpoint, `git status`, branch, and pending Cato/review outputs before continuing, then summarize the loaded checkpoint state to the Operator before taking edit/commit actions.
30. Final readiness synthesizes all phase learning documents and the updated house-style assessment into `docs/yubikit/YUBIKIT_FINAL_READINESS_ASSESSMENT.md`.
31. Reviewer reviews phase output including documentation diffs. Cato additionally audits written artifacts whenever a phase changes files under `docs/yubikit/`, `.github/skills/`, `.github/agents/`, or `.github/tools/`, except local runtime artifacts and `OPERATOR_CONTEXT.local.md`. If phase learnings are written or updated before commit, Cato runs after the learning document is written so the final written-artifact set is audited.
32. Hardware-dependent phases cannot receive an unqualified readiness pass when required hardware verification is unavailable. They must be marked `qualified pass: hardware not run` or `deferred: hardware verification required`, with the gap carried into phase learnings and final readiness.
33. Dual cross-vendor outage creates a transient blocked state. It is not an autonomy level; it overrides the selected autonomy level until cross-vendor gates recover. A waiver during dual outage cannot authorize repository edits, patches, workflow-document edits, commits, or readiness claims; it can only authorize bounded exploratory analysis notes as defined in Claim 11, and must record scope, expiration, and residual risk. If cross-vendor routing is indefinitely unavailable, this workflow is not executable as designed; the Operator must stop and adopt a separately documented replacement review policy before further remediation work proceeds.
34. If the workflow requires Operator input and no answer is available, the default-safe behavior is to stop, leave a checkpoint with the blocked decision and exact next question, and perform no further edits, hardware actions, staging, commits, or pushes.
35. Repeated single-gate waivers are not normal operation. More than one cross-vendor Reviewer or Cato waiver in a phase, or the same gate waived in two consecutive phases, pauses the workflow for Operator escalation and a documented replacement/repair plan before further remediation proceeds.
36. Decision priority order is: explicit system/developer/user safety instructions; no destructive hardware without approval; no repository edits/commits during dual cross-vendor outage; no commit without required review/Cato or phase-scoped waiver where allowed; no staging/commit of protected local/runtime artifacts; no history rewrite/force-push without exact Operator approval; then normal phase autonomy.

## Cato Question

Audit whether this workflow is well thought out, coherent, non-contradictory, and safe enough to approve as the next-stage orchestration plan for a security-sensitive Rust SDK remediation effort.

Focus on:

- contradictions between the artifact set and the claims above
- missing Operator, hardware, commit, quality-gate, or runtime-artifact safeguards
- unclear Engineer, Reviewer, and Cato responsibilities
- weak cross-vendor review handling
- unsafe autonomy assumptions
- missing phase-learning or final-synthesis flow
- Python/UV runner portability risks
- anything that would cause an agent to over-refactor, skip tests, silently skip review, commit unexpectedly, or run unauthorized hardware/destructive operations
