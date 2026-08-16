import { describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { StewardApiClient } from "../api";
import { runDoctor } from "../doctor";
import { describeSecret } from "../format";

// A fake API client that never touches the network. runDoctor only calls
// `.request`; give it a harmless stub so the checks resolve deterministically.
function stubApi(): StewardApiClient {
  return {
    baseUrl: "http://stub.local",
    request: async (_method: string, path: string) => {
      if (path === "/ready") {
        return {
          checks: {
            migrations: { ok: true, detail: { expected: "journal-tip" } },
            redis: { ok: true },
            governedRoutes: {
              ok: true,
              detail: { governedRoutes: 1, nullOperationRoutes: 0, dualModeRoutes: 0 },
            },
            proxyClock: { ok: true, detail: { clockSkewMs: 2 } },
            database: {
              ok: true,
              detail: { clockSkewMs: 1, serverTime: new Date().toISOString() },
            },
          },
        };
      }
      if (path === "/audit/integrity") {
        return {
          valid: true,
          chainValid: true,
          checkpointPresent: true,
          checkpointValid: true,
          checkpointAtHead: true,
          checkpointSeq: 4,
          chainHeadSeq: 4,
        };
      }
      return { ok: true };
    },
  } as unknown as StewardApiClient;
}

/** All contiguous substrings of length >= 4 of `value`. */
function substringsOf(value: string, min = 4): string[] {
  const out: string[] = [];
  for (let len = min; len <= value.length; len++) {
    for (let i = 0; i + len <= value.length; i++) out.push(value.slice(i, i + len));
  }
  return out;
}

describe("describeSecret", () => {
  test("reports missing for empty/undefined and never emits value substrings", () => {
    expect(describeSecret(undefined)).toBe("missing");
    expect(describeSecret("")).toBe("missing");
    const secret = randomBytes(32).toString("hex");
    const desc = describeSecret(secret);
    expect(desc).toBe("present (64 bytes)");
    // No 4+ char substring of the secret may appear in the description.
    for (const sub of [secret.slice(0, 6), secret.slice(-6), secret.slice(10, 20)]) {
      expect(desc.includes(sub)).toBe(false);
    }
  });
});

describe("steward doctor secret redaction", () => {
  test("no >=4-char substring of any secret appears in pretty or JSON output", async () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-doctor-"));
    try {
      // Realistic high-entropy secrets (random hex), so accidental overlaps with
      // field names / static detail strings don't create false positives.
      const secrets: Record<string, string> = {
        STEWARD_MASTER_PASSWORD: randomBytes(32).toString("hex"),
        STEWARD_JWT_SECRET: randomBytes(32).toString("hex"),
        STEWARD_EXECUTION_AUTH_SECRET: `v1:${randomBytes(32).toString("hex")}`,
        STEWARD_KDF_SALT: randomBytes(32).toString("hex"),
        STEWARD_AUDIT_HMAC_KEY: randomBytes(32).toString("hex"),
        STEWARD_AUDIT_SIGNING_KEY: randomBytes(32).toString("hex"),
      };
      const pgPassword = randomBytes(24).toString("hex");
      const databaseUrl = `postgresql://steward:${pgPassword}@postgres:5432/steward`;

      const envPath = join(dir, ".env");
      writeFileSync(
        envPath,
        [
          `DATABASE_URL=${databaseUrl}`,
          ...Object.entries(secrets).map(([k, v]) => `${k}=${v}`),
        ].join("\n") + "\n",
      );

      const result = await runDoctor({ envPath, api: stubApi() });

      const pretty = result.checks.map((c) => `${c.name} ${c.ok} ${c.detail}`).join("\n");
      const jsonOut = JSON.stringify(result);

      const secretValues = [...Object.values(secrets), pgPassword];
      for (const value of secretValues) {
        for (const sub of substringsOf(value)) {
          expect(pretty.includes(sub)).toBe(false);
          expect(jsonOut.includes(sub)).toBe(false);
        }
      }

      // Sanity: the checks still report presence + byte length.
      const master = result.checks.find((c) => c.name === "env:STEWARD_MASTER_PASSWORD");
      expect(master?.ok).toBe(true);
      expect(master?.detail).toBe("present (64 bytes)");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("reports missing required secrets without leaking the ones present", async () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-doctor-"));
    try {
      const present = randomBytes(32).toString("hex");
      const envPath = join(dir, ".env");
      // Only one required secret present; the rest missing.
      writeFileSync(envPath, `STEWARD_MASTER_PASSWORD=${present}\n`);

      const result = await runDoctor({ envPath, api: stubApi() });
      const jsonOut = JSON.stringify(result);

      const jwt = result.checks.find((c) => c.name === "env:STEWARD_JWT_SECRET");
      expect(jwt?.ok).toBe(false);
      expect(jwt?.detail).toBe("missing");

      for (const sub of substringsOf(present)) {
        expect(jsonOut.includes(sub)).toBe(false);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("PR6 governed-route prerequisites (strict)", () => {
  test("passes when exec-auth + audit signing keys present", async () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-doctor-"));
    try {
      const envPath = join(dir, ".env");
      const full: Record<string, string> = {
        DATABASE_URL: "postgresql://steward:pw@postgres:5432/steward",
        STEWARD_MASTER_PASSWORD: randomBytes(32).toString("hex"),
        STEWARD_JWT_SECRET: randomBytes(32).toString("hex"),
        STEWARD_EXECUTION_AUTH_SECRET: `v1:${randomBytes(32).toString("hex")}`,
        STEWARD_KDF_SALT: randomBytes(32).toString("hex"),
        STEWARD_AUDIT_HMAC_KEY: randomBytes(32).toString("hex"),
        STEWARD_AUDIT_SIGNING_KEY: randomBytes(32).toString("hex"),
      };
      writeFileSync(
        envPath,
        `${Object.entries(full)
          .map(([k, v]) => `${k}=${v}`)
          .join("\n")}\n`,
      );
      const ok = await runDoctor({ envPath, strict: true, api: stubApi() });
      const gate = ok.checks.find((c) => c.name === "strict:governed-route-prerequisites");
      expect(gate?.ok).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails closed when the PR4 exec-auth secret is absent", async () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-doctor-"));
    try {
      const envPath = join(dir, ".env");
      writeFileSync(
        envPath,
        [
          "DATABASE_URL=postgresql://steward:pw@postgres:5432/steward",
          `STEWARD_MASTER_PASSWORD=${randomBytes(32).toString("hex")}`,
          `STEWARD_JWT_SECRET=${randomBytes(32).toString("hex")}`,
          `STEWARD_KDF_SALT=${randomBytes(32).toString("hex")}`,
          `STEWARD_AUDIT_HMAC_KEY=${randomBytes(32).toString("hex")}`,
          `STEWARD_AUDIT_SIGNING_KEY=${randomBytes(32).toString("hex")}`,
        ].join("\n") + "\n",
      );
      const res = await runDoctor({ envPath, strict: true, api: stubApi() });
      const gate = res.checks.find((c) => c.name === "strict:governed-route-prerequisites");
      expect(gate?.ok).toBe(false);
      const req = res.checks.find((c) => c.name === "env:STEWARD_EXECUTION_AUTH_SECRET");
      expect(req?.ok).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("operator-integrity diagnostics", () => {
  test("strict mode fails closed for every unavailable or failed operational check", async () => {
    const api = {
      baseUrl: "http://stub.local",
      request: async (_method: string, path: string) => {
        if (path === "/ready") {
          return {
            checks: {
              migrations: { ok: false, detail: { expected: "0084", actual: "0083" } },
              redis: { ok: false, error: "unreachable" },
              governedRoutes: { ok: false, detail: { nullOperationRoutes: 1 } },
              proxyClock: { ok: false, detail: { clockSkewMs: 60_000 } },
              database: {
                ok: false,
                detail: { clockSkewMs: 60_000, serverTime: new Date().toISOString() },
              },
            },
          };
        }
        if (path === "/audit/integrity") {
          return {
            valid: false,
            chainValid: true,
            checkpointPresent: true,
            checkpointValid: true,
            checkpointAtHead: false,
          };
        }
        return { ok: true };
      },
    } as unknown as StewardApiClient;
    const result = await runDoctor({ strict: true, api });
    for (const name of [
      "ops:migration-tip",
      "ops:redis-reachability",
      "ops:governed-route-inventory",
      "ops:proxy-clock-skew",
      "ops:api-database-clock-skew",
      "ops:audit-checkpoint-integrity",
    ]) {
      expect(result.checks.find((check) => check.name === name)?.ok).toBe(false);
    }
    expect(result.ok).toBe(false);
  });
});
