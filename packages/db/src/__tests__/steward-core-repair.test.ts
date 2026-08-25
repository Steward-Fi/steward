import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import postgres from "postgres";

import {
  STEWARD_CORE_REPAIR_CATALOG_SHA256,
  STEWARD_PRODUCTION_ROLLBACK_IMAGE,
  STEWARD_PRODUCTION_ROLLBACK_SOURCE,
  validateStewardCoreRepairOldImageReceipt,
} from "../../scripts/check-steward-core-repair-old-image";
import {
  inspectStewardCoreRepair,
  runStewardCoreRepair,
  type StewardCoreRepairClient,
} from "../steward-core-repair";
import catalogManifest from "../steward-core-repair-catalog.json";
import {
  loadStewardCoreRepairSources,
  quoteStewardCoreRepairIdentifier,
  renderStewardCoreRepairMigration,
  STEWARD_CORE_REPAIR_LEDGER,
  STEWARD_CORE_REPAIR_SOURCES,
  type StewardCoreRepairExecutor,
  type StewardCoreRepairSchema,
  sha256,
  splitStewardMigrationStatements,
} from "../steward-core-repair-sources";
import {
  inspectStewardReleaseReadiness,
  type StewardReleaseReadinessClient,
} from "../steward-release-readiness";
import {
  getStewardSchemaMigrationExpectations,
  runStewardSchemaMigrations,
  type StewardSchemaMigrationClient,
} from "../steward-schema-migrations";

setDefaultTimeout(300_000);

const migrationsFolder = new URL("../../drizzle", import.meta.url).pathname;
const expectedCandidate = {
  image: `ghcr.io/steward-fi/steward@sha256:${"c".repeat(64)}`,
  sourceCommit: "d".repeat(40),
  evidenceArtifactSha256: `sha256:${"a".repeat(64)}`,
};

function renderHistoricalFixture(source: string, schema: StewardCoreRepairSchema): string {
  if (schema === "public") return source;
  const quoted = quoteStewardCoreRepairIdentifier(schema);
  return source
    .replaceAll('"public".', `${quoted}.`)
    .replaceAll("public.", `${quoted}.`)
    .replaceAll("pg_catalog, public", `pg_catalog, ${quoted}`);
}

async function applySource(
  executor: StewardCoreRepairExecutor,
  source: string,
  label: string,
): Promise<void> {
  const statements = splitStewardMigrationStatements(source);
  for (let index = 0; index < statements.length; index += 1) {
    try {
      await executor.unsafe(statements[index] as string);
    } catch (error) {
      throw new Error(`${label} fixture failed at statement ${index + 1}`, { cause: error });
    }
  }
}

async function installHistoricalFloor(
  client: StewardCoreRepairExecutor,
  schema: StewardCoreRepairSchema,
  include0083 = true,
): Promise<void> {
  if (schema !== "public") {
    await client.unsafe(`CREATE SCHEMA ${quoteStewardCoreRepairIdentifier(schema)}`);
  }
  const files = readdirSync(migrationsFolder)
    .filter((file) => /^\d{4}_.+\.sql$/.test(file))
    .filter((file) => Number(file.slice(0, 4)) <= 81)
    .sort();
  for (const file of files) {
    await applySource(
      client,
      renderHistoricalFixture(readFileSync(`${migrationsFolder}/${file}`, "utf8"), schema),
      file,
    );
  }
  if (include0083) {
    await applySource(
      client,
      readFileSync(`${migrationsFolder}/0083_provider_approval_quorum.sql`, "utf8"),
      "0083_provider_approval_quorum",
    );
  }
}

describe("Steward production core-repair source envelope", () => {
  test("pins every source hash and marks only the pre-existing 0083 migration as skipped", () => {
    expect(STEWARD_CORE_REPAIR_SOURCES).toHaveLength(29);
    expect(
      STEWARD_CORE_REPAIR_SOURCES.filter((source) => source.action === "verified_existing").map(
        (source) => source.tag,
      ),
    ).toEqual(["0083_provider_approval_quorum"]);
    expect(() => loadStewardCoreRepairSources("public")).not.toThrow();
    expect(() => loadStewardCoreRepairSources("steward")).not.toThrow();
  });

  test("renders only the reviewed 0091 and 0110 public-schema bindings", () => {
    const source0091 = readFileSync(
      `${migrationsFolder}/0091_external_custody_outcome_reconciliation.sql`,
      "utf8",
    );
    const source0110 = readFileSync(
      `${migrationsFolder}/0110_agent_delete_lease_lifecycle.sql`,
      "utf8",
    );
    const rendered0091 = renderStewardCoreRepairMigration(
      "0091_external_custody_outcome_reconciliation",
      source0091,
      "steward",
    );
    const rendered0110 = renderStewardCoreRepairMigration(
      "0110_agent_delete_lease_lifecycle",
      source0110,
      "steward",
    );

    expect(rendered0091).toContain('ALTER TYPE "steward"."transaction_status"');
    expect(rendered0091).not.toContain('"public"."transaction_status"');
    expect(rendered0110).toContain('FROM "steward".agents');
    expect(rendered0110).toContain('SET search_path = pg_catalog, "steward"');
    expect(rendered0110).not.toContain("public.");
    expect(rendered0110).not.toContain("pg_catalog, public");
  });

  test("retains the independently audited 0084-0110 catalog envelope", () => {
    for (const schema of ["public", "steward"] as const) {
      // PostgreSQL 18 additionally exposes NOT NULL constraints as contype=n.
      // Excluding those representation-only records reproduces the independent
      // production preflight's semantic catalog counts exactly.
      expect(catalogManifest.schemas[schema].changes0084To0110.semanticFinalCounts).toEqual({
        column: 152,
        constraint: 70,
        enum: 1,
        function: 14,
        index: 39,
        relation: 11,
        trigger: 14,
      });
    }
  });
});

function validOldImageCompatibilityReceipt() {
  const probes = {
    health: "pass",
    ready: "pass",
    providerDiscovery: "pass",
    emailSession: "pass",
    passkeySession: "pass",
    sessionRefresh: "pass",
    chatWrite: "pass",
  };
  return {
    proofVersion: 2,
    databaseClass: "isolated-production-restore",
    productionDatabaseTouched: false,
    targetSchema: "steward",
    repairVersion: "prod-core-0082-0110-v1",
    catalogManifestSha256: STEWARD_CORE_REPAIR_CATALOG_SHA256,
    oldImage: {
      image: STEWARD_PRODUCTION_ROLLBACK_IMAGE,
      sourceCommit: STEWARD_PRODUCTION_ROLLBACK_SOURCE,
      automaticMigrationsDisabled: true,
    },
    candidateImage: {
      image: expectedCandidate.image,
      sourceCommit: expectedCandidate.sourceCommit,
      automaticMigrationsDisabled: true,
    },
    preRepair: { ...probes },
    postRepair: { ...probes },
    candidatePostRepair: { ...probes },
    providerExecution: {
      drainedBeforeRepair: true,
      legacyResume: "blocked_by_0084_authority_fence",
      candidateEvidenceResumeAndExecution: "pass",
      rollbackMode: "forward_only_old_image_requires_provider_execution_drain",
    },
    independentReview: {
      reviewedBy: "lalalune",
      disposition: "approved",
      candidateSourceCommit: expectedCandidate.sourceCommit,
      evidenceArtifactSha256: expectedCandidate.evidenceArtifactSha256,
    },
    evidenceArtifactSha256: expectedCandidate.evidenceArtifactSha256,
  };
}

describe("Steward production core-repair old-image gate", () => {
  test("accepts only a reviewed forward-only receipt for the exact rollback image", () => {
    expect(
      sha256(readFileSync(new URL("../steward-core-repair-catalog.json", import.meta.url), "utf8")),
    ).toBe(STEWARD_CORE_REPAIR_CATALOG_SHA256);
    expect(
      validateStewardCoreRepairOldImageReceipt(
        validOldImageCompatibilityReceipt(),
        expectedCandidate,
      ),
    ).toEqual(validOldImageCompatibilityReceipt());
  });

  test("fails closed on image drift, missing probes, or a claimed full rollback", () => {
    const wrongImage = validOldImageCompatibilityReceipt();
    wrongImage.oldImage.image = `ghcr.io/steward-fi/steward@sha256:${"b".repeat(64)}`;
    expect(() => validateStewardCoreRepairOldImageReceipt(wrongImage, expectedCandidate)).toThrow(
      "does not pin the production rollback image",
    );

    const wrongCandidate = validOldImageCompatibilityReceipt();
    wrongCandidate.candidateImage.sourceCommit = "e".repeat(40);
    expect(() =>
      validateStewardCoreRepairOldImageReceipt(wrongCandidate, expectedCandidate),
    ).toThrow("does not pin the approved candidate image");

    const missingProbe = validOldImageCompatibilityReceipt();
    missingProbe.candidatePostRepair.passkeySession = "fail";
    expect(() => validateStewardCoreRepairOldImageReceipt(missingProbe, expectedCandidate)).toThrow(
      "probe passkeySession is not green",
    );

    const unboundReview = validOldImageCompatibilityReceipt();
    unboundReview.independentReview.candidateSourceCommit = "f".repeat(40);
    expect(() =>
      validateStewardCoreRepairOldImageReceipt(unboundReview, expectedCandidate),
    ).toThrow("independent approval bound to the candidate and evidence");

    const unsafeRollbackClaim = validOldImageCompatibilityReceipt();
    unsafeRollbackClaim.providerExecution.rollbackMode = "full_rollback";
    expect(() =>
      validateStewardCoreRepairOldImageReceipt(unsafeRollbackClaim, expectedCandidate),
    ).toThrow("does not prove the governed-action boundary");

    const wrongEvidence = validOldImageCompatibilityReceipt();
    wrongEvidence.evidenceArtifactSha256 = `sha256:${"f".repeat(64)}`;
    expect(() =>
      validateStewardCoreRepairOldImageReceipt(wrongEvidence, expectedCandidate),
    ).toThrow("evidence artifact hash does not match the file");
  });
});

function createSchemaMismatchClient(
  resolvedSchema: StewardCoreRepairSchema,
  options: {
    unlockSucceeds?: boolean;
    acquisitionThrows?: boolean;
    beginThrows?: boolean;
    rollbackThrows?: boolean;
  } = {},
) {
  const trace: string[] = [];
  const transaction = {
    async unsafe(query: string) {
      if (query.startsWith("SET TRANSACTION")) trace.push("transaction:isolation");
      else if (query.startsWith("SET LOCAL lock_timeout")) trace.push("transaction:lock-timeout");
      else if (query.startsWith("SET LOCAL statement_timeout")) {
        trace.push("transaction:statement-timeout");
      } else if (query.startsWith("SET LOCAL idle_in_transaction")) {
        trace.push("transaction:idle-timeout");
      } else if (query.startsWith("LOCK TABLE")) trace.push("transaction:baseline-locks");
      else if (query === "SELECT pg_catalog.to_regclass($1)::text AS relation_name") {
        trace.push("transaction:optional-table-check");
        return [{ relation_name: null }];
      } else if (query === "SELECT pg_catalog.current_schema()::text AS schema_name") {
        trace.push("transaction:resolve-schema");
        return [{ schema_name: resolvedSchema }];
      } else if (query.startsWith("SET LOCAL search_path")) {
        trace.push("transaction:set-search-path");
      } else {
        throw new Error(`unexpected fake transaction query: ${query}`);
      }
      return [];
    },
  } as unknown as StewardCoreRepairExecutor;

  const reserved = {
    async unsafe(query: string, parameters?: unknown[]) {
      if (
        query ===
        "SELECT pg_catalog.pg_try_advisory_lock(pg_catalog.hashtextextended($1, 0)) AS acquired"
      ) {
        trace.push("reserved:lock");
        if (options.acquisitionThrows) throw new Error("simulated acquisition response loss");
        return [{ acquired: true }];
      }
      if (
        query ===
        "SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1, 0)) AS released"
      ) {
        trace.push("reserved:unlock");
        return [{ released: options.unlockSucceeds ?? true }];
      }
      if (query === "BEGIN") {
        trace.push("reserved:begin");
        if (options.beginThrows) throw new Error("simulated BEGIN response loss");
        return [];
      }
      if (query === "COMMIT") {
        trace.push("reserved:commit");
        return [];
      }
      if (query === "ROLLBACK") {
        trace.push("reserved:rollback");
        if (options.rollbackThrows) throw new Error("simulated ROLLBACK failure");
        return [];
      }
      return transaction.unsafe(query, parameters);
    },
    release() {
      trace.push("reserved:release");
    },
  };

  const client = {
    async unsafe(query: string) {
      throw new Error(`pooled connection must not execute repair query: ${query}`);
    },
    async begin<T>(callback: (executor: StewardCoreRepairExecutor) => Promise<T>): Promise<T> {
      trace.push("pooled:begin");
      return callback(transaction);
    },
    async reserve() {
      trace.push("pooled:reserve");
      return reserved;
    },
    async end() {
      trace.push("pooled:end");
    },
  } as unknown as StewardCoreRepairClient;

  return { client, trace };
}

describe("Steward production core-repair connection safeguards", () => {
  test("uses one reserved session for advisory lock, transaction, and unlock", async () => {
    const { client, trace } = createSchemaMismatchClient("steward");

    await expect(runStewardCoreRepair({ expectedSchema: "public", client })).rejects.toThrow(
      "target schema mismatch",
    );

    expect(trace).toEqual([
      "pooled:reserve",
      "reserved:lock",
      "reserved:begin",
      "transaction:isolation",
      "transaction:lock-timeout",
      "transaction:statement-timeout",
      "transaction:idle-timeout",
      "transaction:baseline-locks",
      "transaction:optional-table-check",
      "transaction:resolve-schema",
      "reserved:rollback",
      "reserved:unlock",
      "reserved:release",
    ]);
  });

  test("checks the connection target before setting the transaction search path", async () => {
    const { client, trace } = createSchemaMismatchClient("steward");

    await expect(
      runStewardCoreRepair({
        expectedSchema: "public",
        client,
        useAdvisoryLock: false,
      }),
    ).rejects.toThrow("target schema mismatch");

    expect(trace.indexOf("transaction:baseline-locks")).toBeGreaterThanOrEqual(0);
    expect(trace.indexOf("transaction:resolve-schema")).toBeGreaterThan(
      trace.indexOf("transaction:baseline-locks"),
    );
    expect(trace).not.toContain("transaction:set-search-path");
  });

  test("quarantines the client instead of pooling a session when advisory unlock fails", async () => {
    const { client, trace } = createSchemaMismatchClient("steward", {
      unlockSucceeds: false,
    });

    await expect(runStewardCoreRepair({ expectedSchema: "public", client })).rejects.toThrow(
      "reserved advisory lock could not be released",
    );

    expect(trace).toContain("pooled:end");
    expect(trace).not.toContain("reserved:release");
  });

  test("quarantines an uncertain advisory-lock acquisition", async () => {
    const { client, trace } = createSchemaMismatchClient("steward", {
      acquisitionThrows: true,
    });

    await expect(runStewardCoreRepair({ expectedSchema: "public", client })).rejects.toThrow(
      "simulated acquisition response loss",
    );

    expect(trace).toContain("pooled:end");
    expect(trace).not.toContain("reserved:unlock");
    expect(trace).not.toContain("reserved:release");
  });

  test("quarantines a transaction whose BEGIN and cleanup outcomes are both uncertain", async () => {
    const { client, trace } = createSchemaMismatchClient("steward", {
      beginThrows: true,
      rollbackThrows: true,
    });

    await expect(runStewardCoreRepair({ expectedSchema: "public", client })).rejects.toThrow(
      "transaction start was uncertain",
    );

    expect(trace).toContain("reserved:unlock");
    expect(trace).toContain("pooled:end");
    expect(trace).not.toContain("reserved:release");
  });
});

const postgresUrl = process.env.DATABASE_URL;
const postgresDescribe = postgresUrl ? describe : describe.skip;

postgresDescribe("Steward production core repair on disposable PostgreSQL", () => {
  const originalUrl = new URL(postgresUrl ?? "postgres://unused.invalid/postgres");
  const maintenanceUrl = new URL(originalUrl);
  maintenanceUrl.pathname = "/postgres";
  maintenanceUrl.searchParams.delete("options");
  const admin = postgres(maintenanceUrl.toString(), {
    max: 1,
    prepare: false,
    onnotice: () => {},
  });
  const databases: string[] = [];
  const roles: string[] = [];

  afterAll(async () => {
    for (const database of databases) {
      await admin.unsafe(
        `DROP DATABASE IF EXISTS ${quoteStewardCoreRepairIdentifier(database)} WITH (FORCE)`,
      );
    }
    for (const role of roles) {
      await admin.unsafe(`DROP ROLE IF EXISTS ${quoteStewardCoreRepairIdentifier(role)}`);
    }
    await admin.end({ timeout: 5 });
  });

  async function createUntrustedRole(): Promise<string> {
    const role = `repair_attacker_${randomUUID().replaceAll("-", "")}`;
    roles.push(role);
    await admin.unsafe(`CREATE ROLE ${quoteStewardCoreRepairIdentifier(role)}`);
    return role;
  }

  async function createFixture(schema: StewardCoreRepairSchema, include0083 = true) {
    const database = `steward_core_repair_test_${schema}_${randomUUID().replaceAll("-", "")}`;
    databases.push(database);
    await admin.unsafe(`CREATE DATABASE ${quoteStewardCoreRepairIdentifier(database)}`);
    const targetUrl = new URL(originalUrl);
    targetUrl.pathname = `/${database}`;
    const searchPath = schema === "public" ? "public,pg_catalog" : `${schema},public,pg_catalog`;
    targetUrl.searchParams.set("options", `-c search_path=${searchPath}`);
    const client = postgres(targetUrl.toString(), {
      max: 1,
      prepare: false,
      onnotice: () => {},
    });
    await installHistoricalFloor(
      client as unknown as StewardCoreRepairExecutor,
      schema,
      include0083,
    );
    return { client, database };
  }

  test("rejects a search-path schema that shadows current_schema", async () => {
    const { client } = await createFixture("public");
    try {
      await client.unsafe(`
        CREATE SCHEMA shadow_test;
        CREATE FUNCTION shadow_test.current_schema()
        RETURNS name
        LANGUAGE sql
        IMMUTABLE
        AS $$ SELECT 'public'::name $$;
        SET search_path TO shadow_test, public, pg_catalog
      `);

      await expect(
        inspectStewardCoreRepair({
          expectedSchema: "public",
          client: client as unknown as StewardCoreRepairClient,
        }),
      ).rejects.toThrow("unsupported core-repair schema shadow_test");
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("rejects an unreviewed CREATE grant on the repair target schema", async () => {
    const { client } = await createFixture("steward");
    const role = await createUntrustedRole();
    try {
      await client.unsafe(
        `GRANT CREATE ON SCHEMA steward TO ${quoteStewardCoreRepairIdentifier(role)}`,
      );

      await expect(
        inspectStewardCoreRepair({
          expectedSchema: "steward",
          client: client as unknown as StewardCoreRepairClient,
        }),
      ).rejects.toThrow("target schema grants CREATE to an unreviewed role");
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("rejects target-schema objects owned by an unreviewed role", async () => {
    const { client } = await createFixture("steward");
    const role = await createUntrustedRole();
    const quotedRole = quoteStewardCoreRepairIdentifier(role);
    try {
      await client.unsafe(`
        GRANT USAGE, CREATE ON SCHEMA steward TO ${quotedRole};
        SET ROLE ${quotedRole};
        CREATE FUNCTION steward.lower(text)
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        AS $$ SELECT 'shadowed'::text $$;
        RESET ROLE;
        REVOKE USAGE, CREATE ON SCHEMA steward FROM ${quotedRole};
      `);

      await expect(
        inspectStewardCoreRepair({
          expectedSchema: "steward",
          client: client as unknown as StewardCoreRepairClient,
        }),
      ).rejects.toThrow("target schema contains objects owned by an unreviewed role");
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("rejects target-schema types owned by an unreviewed role", async () => {
    const { client } = await createFixture("steward");
    const role = await createUntrustedRole();
    const quotedRole = quoteStewardCoreRepairIdentifier(role);
    try {
      await client.unsafe(`
        GRANT USAGE, CREATE ON SCHEMA steward TO ${quotedRole};
        SET ROLE ${quotedRole};
        CREATE TYPE steward.shadow_enum AS ENUM ('shadowed');
        RESET ROLE;
        REVOKE USAGE, CREATE ON SCHEMA steward FROM ${quotedRole};
      `);

      await expect(
        inspectStewardCoreRepair({
          expectedSchema: "steward",
          client: client as unknown as StewardCoreRepairClient,
        }),
      ).rejects.toThrow("target schema contains objects owned by an unreviewed role");
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("rejects target-object grants that can preinstall or invoke unreviewed behavior", async () => {
    const { client } = await createFixture("steward");
    const role = await createUntrustedRole();
    const quotedRole = quoteStewardCoreRepairIdentifier(role);
    const inspect = () =>
      inspectStewardCoreRepair({
        expectedSchema: "steward",
        client: client as unknown as StewardCoreRepairClient,
      });
    try {
      await client.unsafe(`GRANT TRIGGER ON steward.agents TO ${quotedRole}`);
      await expect(inspect()).rejects.toThrow(
        "target objects grant privileges to an unreviewed role",
      );
      await client.unsafe(`REVOKE TRIGGER ON steward.agents FROM ${quotedRole}`);

      await client.unsafe(`GRANT UPDATE (name) ON steward.agents TO ${quotedRole}`);
      await expect(inspect()).rejects.toThrow(
        "target objects grant privileges to an unreviewed role",
      );
      await client.unsafe(`REVOKE UPDATE (name) ON steward.agents FROM ${quotedRole}`);

      await client.unsafe(
        `GRANT EXECUTE ON FUNCTION steward.steward_provider_action_binding_guard() TO ${quotedRole}`,
      );
      await expect(inspect()).rejects.toThrow(
        "target objects grant privileges to an unreviewed role",
      );
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("keeps pg_catalog ahead of a runtime-owned target-schema builtin shadow", async () => {
    const { client } = await createFixture("steward");
    try {
      await client.unsafe(`
        CREATE FUNCTION steward.lower(text)
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        AS $$ SELECT 'shadowed'::text $$;
        INSERT INTO steward.tenants (id, name, api_key_hash)
        VALUES ('tenant-shadow-fixture', 'Shadow fixture', 'shadow-fixture-key');
        INSERT INTO steward.agents (id, tenant_id, name, wallet_address)
        VALUES (
          'agent-shadow-fixture',
          'tenant-shadow-fixture',
          'Shadow fixture',
          '0x3333333333333333333333333333333333333333'
        );
        INSERT INTO steward.evm_wallet_nonces (wallet_address, chain_id, next_nonce)
        VALUES ('0x3333333333333333333333333333333333333333', 1, 1);
      `);

      const inspection = await inspectStewardCoreRepair({
        expectedSchema: "steward",
        client: client as unknown as StewardCoreRepairClient,
      });

      expect(inspection.status).toBe("eligible");
      expect(inspection.preflight?.evmNonceNamespaces).toBe(1);
      expect(inspection.preflight?.unresolvedEvmNonceNamespaces).toBe(0);
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  for (const schema of ["public", "steward"] as const) {
    test(`repairs the ${schema} discontinuity atomically and preserves the shared ledger`, async () => {
      const { client } = await createFixture(schema);
      const quotedSchema = quoteStewardCoreRepairIdentifier(schema);
      try {
        await client.unsafe(`
          CREATE SCHEMA drizzle;
          CREATE TABLE drizzle.__drizzle_migrations (
            id serial PRIMARY KEY,
            hash text NOT NULL,
            created_at bigint
          );
          INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
          VALUES ('shared-eliza-sentinel', 1793072800004);
          INSERT INTO ${quotedSchema}.tenants (id, name, api_key_hash)
          VALUES ('tenant-repair-fixture', 'Repair fixture', 'fixture-key');
          INSERT INTO ${quotedSchema}.agents (id, tenant_id, name, wallet_address)
          VALUES (
            'agent-repair-fixture',
            'tenant-repair-fixture',
            'Repair fixture',
            '0x1111111111111111111111111111111111111111'
          );
          INSERT INTO ${quotedSchema}.evm_wallet_nonces (wallet_address, chain_id, next_nonce)
          VALUES ('0x1111111111111111111111111111111111111111', 1, 7);
        `);

        const inspection = await inspectStewardCoreRepair({
          expectedSchema: schema,
          client: client as unknown as StewardCoreRepairClient,
        });
        expect(inspection.status).toBe("eligible");
        expect(inspection.preflight?.evmNonceNamespaces).toBe(1);
        const dryRunState = await client.unsafe<
          {
            version_exists: boolean;
            ledger_exists: boolean;
          }[]
        >(`
          SELECT
            EXISTS (
              SELECT 1 FROM pg_catalog.pg_attribute attribute
              JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
              WHERE relation.oid = '${schema}.execution_authorization_nonces'::regclass
                AND attribute.attname = 'version'
                AND attribute.attnum > 0 AND NOT attribute.attisdropped
            ) AS version_exists,
            to_regclass('${schema}.${STEWARD_CORE_REPAIR_LEDGER}') IS NOT NULL AS ledger_exists
        `);
        expect(dryRunState).toEqual([{ version_exists: false, ledger_exists: false }]);

        const first = await runStewardCoreRepair({
          expectedSchema: schema,
          client: client as unknown as StewardCoreRepairClient,
        });
        expect(first.status).toBe("applied");
        expect(first.applied).toHaveLength(28);
        expect(first.verifiedExisting).toEqual(["0083_provider_approval_quorum"]);
        expect(first.preflight).toEqual({
          executionReadyWithoutPolicyEvidence: 0,
          externalCustodyNoncesWithoutIdentityDigest: 0,
          googleOperationsNeedingRiskUpgrade: 0,
          evmNonceNamespaces: 1,
          unresolvedEvmNonceNamespaces: 0,
        });
        const systemCatalogLeak = await client.unsafe<{ leaked_relation: string | null }[]>(`
          SELECT pg_catalog.to_regclass(
            'pg_catalog.provider_action_reservation_generations'
          )::text AS leaked_relation
        `);
        expect(systemCatalogLeak).toEqual([{ leaked_relation: null }]);
        const advisoryLocks = await client.unsafe<{ count: number }[]>(`
          SELECT count(*)::int AS count
          FROM pg_catalog.pg_locks
          WHERE locktype = 'advisory' AND pid = pg_backend_pid()
        `);
        expect(advisoryLocks).toEqual([{ count: 0 }]);

        const ledger = await client.unsafe<
          {
            migration_order: number;
            tag: string;
            action: string;
            source_hash: string;
            rendered_hash: string;
            bundle_hash: string;
          }[]
        >(`
          SELECT migration_order, tag, action, source_hash, rendered_hash, bundle_hash
          FROM ${quotedSchema}.${quoteStewardCoreRepairIdentifier(STEWARD_CORE_REPAIR_LEDGER)}
          ORDER BY migration_order
        `);
        expect(ledger).toHaveLength(29);
        expect(ledger[1]?.tag).toBe("0083_provider_approval_quorum");
        expect(ledger[1]?.action).toBe("verified_existing");
        expect(new Set(ledger.map((row) => row.bundle_hash))).toEqual(new Set([first.bundleHash]));
        for (const row of ledger) {
          expect(row.source_hash).toMatch(/^[0-9a-f]{64}$/);
          expect(row.rendered_hash).toMatch(/^[0-9a-f]{64}$/);
        }

        const sharedLedger = await client.unsafe<{ hash: string; created_at: string }[]>(
          "SELECT hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id",
        );
        expect(sharedLedger).toEqual([
          { hash: "shared-eliza-sentinel", created_at: "1793072800004" },
        ]);

        const nonceOwner = await client.unsafe<
          {
            tenant_id: string;
            wallet_address: string;
            chain_id: number;
          }[]
        >(`
          SELECT tenant_id, wallet_address, chain_id
          FROM ${quotedSchema}.evm_wallet_nonce_owners
        `);
        expect(nonceOwner).toEqual([
          {
            tenant_id: "tenant-repair-fixture",
            wallet_address: "0x1111111111111111111111111111111111111111",
            chain_id: 1,
          },
        ]);

        const outcomeUnknown = await client.unsafe<{ count: number }[]>(`
          SELECT count(*)::int AS count
          FROM pg_catalog.pg_type type_record
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = type_record.typnamespace
          JOIN pg_catalog.pg_enum enum_record ON enum_record.enumtypid = type_record.oid
          WHERE namespace.nspname = '${schema}'
            AND type_record.typname = 'transaction_status'
            AND enum_record.enumlabel = 'outcome_unknown'
        `);
        expect(outcomeUnknown).toEqual([{ count: 1 }]);

        const functions = await client.unsafe<{ function_name: string; settings: string }[]>(`
          SELECT
            procedure.proname AS function_name,
            COALESCE(array_to_string(procedure.proconfig, ','), '') AS settings
          FROM pg_catalog.pg_proc procedure
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
          WHERE namespace.nspname = '${schema}'
            AND procedure.proname IN (
              'steward_lock_tenant_deletion',
              'steward_fence_agent_authority_creation',
              'steward_fence_upstream_lease_workspace',
              'steward_fence_provider_action_intent_tenant',
              'steward_fence_provider_action_agent',
              'steward_guard_agent_delete',
              'steward_guard_workspace_delete'
            )
          ORDER BY procedure.proname
        `);
        expect(functions).toHaveLength(7);
        for (const fn of functions) {
          expect(fn.settings).toContain(`search_path=pg_catalog, ${schema}`);
        }

        const second = await runStewardCoreRepair({
          expectedSchema: schema,
          client: client as unknown as StewardCoreRepairClient,
        });
        expect(second).toEqual({
          status: "already_applied",
          schema,
          bundleHash: first.bundleHash,
          applied: [],
          verifiedExisting: ["0083_provider_approval_quorum"],
          preflight: null,
        });

        await runStewardSchemaMigrations({
          client: client as unknown as StewardSchemaMigrationClient,
          expectedSchema: schema,
          useAdvisoryLock: false,
        });
        const releaseReadiness = await inspectStewardReleaseReadiness({
          expectedSchema: schema,
          client: client as unknown as StewardReleaseReadinessClient,
        });
        expect(releaseReadiness).toMatchObject({
          status: "ready",
          schema,
          core: { status: "already_applied", schema },
          authSchema: {
            status: "ready",
            schema,
            expectedCount: getStewardSchemaMigrationExpectations().length,
            appliedCount: getStewardSchemaMigrationExpectations().length,
            forwardCount: 0,
            expectedTip: "0001_passkey_rp_provenance_0114",
            rpProvenance: true,
          },
        });

        // A physically missing RP provenance column must fail readiness even
        // while both Steward-owned marker chains and the unrelated shared
        // Eliza ledger remain present and unchanged.
        await client.unsafe(`ALTER TABLE ${quotedSchema}.authenticators DROP COLUMN rp_id`);
        await expect(
          inspectStewardReleaseReadiness({
            expectedSchema: schema,
            client: client as unknown as StewardReleaseReadinessClient,
          }),
        ).rejects.toThrow(/authenticators\.rp_id/);

        const sharedLedgerAfterReadiness = await client.unsafe<
          { hash: string; created_at: string }[]
        >("SELECT hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id");
        expect(sharedLedgerAfterReadiness).toEqual([
          { hash: "shared-eliza-sentinel", created_at: "1793072800004" },
        ]);
      } finally {
        await client.end({ timeout: 5 });
      }
    });
  }

  test("fails closed when 0083 is absent and leaves 0082 unapplied", async () => {
    const { client } = await createFixture("public", false);
    try {
      await expect(
        runStewardCoreRepair({
          expectedSchema: "public",
          client: client as unknown as StewardCoreRepairClient,
        }),
      ).rejects.toThrow(
        /0083 existing-state exact catalog envelope mismatch|0082-absent\/0083-present/,
      );

      const state = await client.unsafe<
        {
          version_exists: boolean;
          ledger_exists: boolean;
        }[]
      >(`
        SELECT
          EXISTS (
            SELECT 1 FROM pg_catalog.pg_attribute attribute
            JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
            WHERE relation.oid = 'public.execution_authorization_nonces'::regclass
              AND attribute.attname = 'version'
              AND attribute.attnum > 0 AND NOT attribute.attisdropped
          ) AS version_exists,
          to_regclass('public.${STEWARD_CORE_REPAIR_LEDGER}') IS NOT NULL AS ledger_exists
      `);
      expect(state).toEqual([{ version_exists: false, ledger_exists: false }]);
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("fails closed on an unresolved nonce namespace before any DDL is retained", async () => {
    const { client } = await createFixture("steward");
    try {
      await client.unsafe(`
        INSERT INTO steward.evm_wallet_nonces (wallet_address, chain_id, next_nonce)
        VALUES ('0x2222222222222222222222222222222222222222', 1, 1)
      `);
      await expect(
        runStewardCoreRepair({
          expectedSchema: "steward",
          client: client as unknown as StewardCoreRepairClient,
        }),
      ).rejects.toThrow("data preflight differs from the reviewed production envelope");

      const state = await client.unsafe<
        {
          version_exists: boolean;
          ledger_exists: boolean;
        }[]
      >(`
        SELECT
          EXISTS (
            SELECT 1 FROM pg_catalog.pg_attribute attribute
            JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
            WHERE relation.oid = 'steward.execution_authorization_nonces'::regclass
              AND attribute.attname = 'version'
              AND attribute.attnum > 0 AND NOT attribute.attisdropped
          ) AS version_exists,
          to_regclass('steward.${STEWARD_CORE_REPAIR_LEDGER}') IS NOT NULL AS ledger_exists
      `);
      expect(state).toEqual([{ version_exists: false, ledger_exists: false }]);
    } finally {
      await client.end({ timeout: 5 });
    }
  });
});
