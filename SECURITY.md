# Security Policy

## Supported versions

Security fixes are applied to the latest code on `develop` and promoted to
`main` after validation. Older commits, forks, and unpublished builds are not
maintained security releases. Operators should run the latest promoted
`main` revision and apply security updates promptly.

## Reporting a vulnerability

Do not open a public issue or discussion for a suspected vulnerability.
Use GitHub's private vulnerability reporting form in this repository's
**Security** tab so maintainers can investigate without exposing users before
a fix is available:

https://github.com/Steward-Fi/steward/security/advisories/new

Include, when possible:

- the affected revision, package, route, or deployment mode;
- reproduction steps or a minimal proof of concept;
- the expected and observed security behavior;
- impact, prerequisites, and whether exploitation was observed; and
- any suggested remediation or regression test.

Never include real production credentials, private keys, personal data, or
funds in a report. Use clearly fake canaries and redact logs before attaching
them.

Maintainers will coordinate disclosure and credit through the private advisory.
Please allow time for triage, a tested fix, and downstream deployment before
publishing details.

## Scope notes

Reports about authentication, authorization, tenant isolation, policy bypass,
credential handling, signing or custody, replay/idempotency, SSRF, webhook
integrity, supply-chain controls, and sensitive-data leakage are in scope.
Operational questions and non-security bugs should use the normal issue
tracker.
