# Copilot + Markdown security policy (enhanced)

An independent public copy, not a fork, of
[copilot-policy-gate-demo](https://github.com/ShawnMcGough/copilot-policy-gate-demo)
for future enhancements. All 10 source branch heads and their reachable Git
history were copied; the source had no tags. Source `main` snapshot:
`81b7b13c52d90d56054629e80536d55a72895a94`. The original shared repository was
left unchanged.

A deliberately simple demonstration of branch protection using GitHub Copilot
and an organization security standard in a Markdown file. Copilot reviews PR changes against a 
[organization policy](security/organization-standards.md). One required GitHub
Actions check, **Organization Security Standard**, fails and blocks merging into
protected `main` when the policy is violated via a GitHub Copilot review.

## How it works

The [Actions workflow](.github/workflows/security-compliance.yml) has
**one job**, with sequential steps. `pull_request_target` runs its YAML from the
trusted base revision, not the PR's proposed workflow:

1. Read the policy from the PR's trusted **base commit** and collect the PR diff
   with surrounding context. Proposed policy edits do not change this review.
2. Run the official `@github/copilot` CLI with `claude-haiku-5.5` (configurable), using the existing
   `COPILOT_GITHUB_TOKEN` secret. PR files are data: never checked out, installed,
   or executed. Copilot has no tools and loads no repository instructions.
3. Validate Copilot's JSON response with a small inline `jq` check. Show findings
   and fixes in the job summary/log, then fail for any violation, incomplete
   review, missing/malformed result, or CLI error.

CLI exit code zero alone is **not** compliance. A passing job requires a valid,
complete report with zero violations. The CLI's `--output-format json` is an
event stream, not a policy verdict: `jq` extracts and validates the single
assistant response after a clean CLI completion. There is no built-in
fail-on-policy flag.

Steps appear inside the job's **Details**, not as separate PR checks.
The native job conclusion is the required check.

## Weekly main snapshot audit

The separate [snapshot workflow](.github/workflows/security-snapshot.yml) runs
**Mondays at 09:17 UTC** (`17 9 * * 1`). After it is merged into the default
`main` branch, it can also be started through **Actions > Copilot main snapshot
audit > Run workflow**, selecting **main**. Other dispatch refs are rejected
before credentialed review. Scheduled runs can be delayed by GitHub.

Each run resolves current `main` once and reads every tracked file and the policy
from that commit as text, without executing snapshot code or dependencies.
Unchanged problems are in scope, so a merged policy update applies to existing
code at the next audit. Copilot uses the same pinned CLI/model, isolated no-tools
review, token, ten-minute job timeout, and thirty-credit cap as the PR demo.
The CLI has a five-minute deadline to leave time for reporting.

Open **Main Security Snapshot Audit > Summary** for the commit, policy blob,
file/line coverage inventory, findings, remediation, and **PASS**, **FAIL**,
**INCOMPLETE**, or **ERROR** result. Violations, incomplete coverage, malformed
output, and CLI failures fail the job. Raw snapshot content and CLI output are
not published. This is reporting on already merged code, **not another required
PR gate**; leave **Organization Security Standard** as the sole required check.

This deliberately small audit rejects binary/non-UTF-8 files, symlinks,
submodules, LFS pointers, and oversized input rather than skipping or truncating
them. Limits are 200 tracked files, 128 KiB total file content, and 256 KiB of
numbered review input. A complete inventory and Copilot's claimed coverage are
not proof that no issues exist.

If repository Actions event restrictions apply, an administrator must allow
`schedule` and `workflow_dispatch` for the new workflow before it can run.
This change does not modify event policies or branch protections, and does not
activate a schedule until the workflow is on `main`.

## Try the demo

Open a same-repository PR targeting `main`, then open **Checks > Organization
Security Standard > Details** and its job summary.

- Use parameterized SQL: pass.
- Replace parameter binding with SQL string interpolation: fail **SEC-001**, with
  the file/line, explanation, and a concrete fix.
- Restore parameter binding and push a new commit: receive a fresh review.
- Propose weaker policy alongside unsafe SQL: the base policy still applies.

Original-repository demo PRs (not copied): [#16, safe parameterized SQL](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/16)
passes; [#17, intentionally unsafe SQL](https://github.com/ShawnMcGough/copilot-policy-gate-demo/pull/17)
is blocked for **SEC-001** (high) at `src/example.py:22`. Each shows the single
native **Organization Security Standard** check.

## Setup

Git-tracked workflows and policy files are separate from GitHub settings.
Credentials/secrets, account permissions, issues/PRs, and Actions event policies
were not copied. No ruleset is active in this new repository. **Actions is
disabled** to prevent bootstrap and scheduled runs; enable it only when ready.

1. Use a Copilot-enabled account and save a fine-grained PAT with **Account
   permissions > Copilot Requests: Read** as the Actions secret
   `COPILOT_GITHUB_TOKEN`. This personal-account demo does not use
   organization-billed `GITHUB_TOKEN` inference or a separate model-provider key.
2. Enable Actions in this repository's settings when ready to run the demo.
   If an Actions event policy restricts workflow execution, allow
   `pull_request_target` for `.github/workflows/security-compliance.yml`.
3. Import the ruleset below when ready to enforce protections. After a genuine
   run, verify **Organization Security Standard** is emitted by the expected
   GitHub Actions App (**15368** in the export).
4. Use trusted same-repository collaborators only. Fork PRs fail before
   credentialed analysis; the required job is not skipped to green.

### Ruleset snapshot and import

[`.github/rulesets/protected-main.json`](.github/rulesets/protected-main.json)
is an import-ready snapshot of the
[source ruleset](https://github.com/ShawnMcGough/copilot-policy-gate-demo/rules/26989916)
(ID `26989916`), fetched on 2026-11-12. It preserves the name, target,
enforcement, matching conditions, every rule parameter, and bypass actors;
server-generated identity, source, timestamps, and URL metadata are omitted.

Download the JSON, then in **this new repository** open **Settings** and the
**Rulesets** page. Choose **New ruleset > Import a ruleset**, select the file,
review, and click **Create** when ready. The export retains
`"enforcement": "active"`: creating the imported
ruleset activates its protections, including the required check. **Committing
the JSON alone does not activate anything.** No import was performed; configuring
`COPILOT_GITHUB_TOKEN` and other Actions settings remains a separate setup step.

Keep the token's entitlement, expiry, and spending controls current. The job has a
ten-minute timeout and a thirty-AI-credit CLI limit; usage can still be billable.

## Deliberate limits

This is a small **trusted-collaborator demo**, not production-grade enforcement.
Same-repository admission limits credentialed, potentially billable runs; it is
not a security guarantee or a defense against malicious collaborators.
The workflow and policy come from the trusted base, so a PR cannot change its own
evaluator. Administrators can change protections, and another workflow can use the
same check name. Review workflow/policy changes carefully before merging them into
the protected base; this is not tamper-proof enforcement against trusted actors.

Copilot can miss issues or be influenced by adversarial text. Green means a
complete review reported no violations, not proof of secure code. Large or
unsupported diffs may fail or need a smaller PR. There is no custom atomic
rerun-invalidation mechanism; use fresh commits for the demo and the latest
required result. After fixing credentials or infrastructure, rerun the job.

## References

- [Official direct CLI Actions example](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli-in-actions)
- [Required status check semantics](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
