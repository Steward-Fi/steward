# SOC2 Evidence Collection

Steward cannot grant SOC2 certification from code alone. Certification requires
organizational controls, auditor review, vendor management, incident-response
records, and operating evidence outside this repository.

The repo does include an OSS evidence collector for technical controls:

```sh
bun run scripts/soc2-check.ts --json --out soc2-evidence.json
```

For local/offline development where dependency-audit commands are intentionally
skipped:

```sh
bun run scripts/soc2-check.ts --json --skip-dependency-checks
```

In `NODE_ENV=production`, dependency skips fail closed unless the operator sets
`STEWARD_SOC2_ALLOW_DEPENDENCY_SKIP=true`. `--strict` also treats any skipped
check as a failing gate, even outside production.

The report includes:

- `generatedAt`, `gitRevision`, `nodeEnv`, and status counts.
- Environment checks for master password, JWT secret, KDF salt, audit HMAC key,
  database TLS, and bind-host posture.
- Source-backed checks for security headers, audit tamper-evidence, and
  retention/deletion controls, including fail-closed pre-delete audit
  authorization for destructive retention sweeps.
- Dependency and lockfile checks unless `--skip-dependency-checks` is supplied.

Use the generated JSON as supporting evidence for auditor review. It is not a
replacement for policy documents, access reviews, vendor reviews, incident
records, penetration tests, or a formal SOC2 report.
