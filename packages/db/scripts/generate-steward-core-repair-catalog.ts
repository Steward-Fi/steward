import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import postgres from "postgres";

import {
  loadStewardCoreRepairSources,
  mapStewardCatalog,
  queryStewardCatalog,
  quoteStewardCoreRepairIdentifier,
  STEWARD_CORE_REPAIR_SOURCE_HEAD,
  STEWARD_CORE_REPAIR_VERSION,
  type StewardCatalogRecord,
  type StewardCoreRepairExecutor,
  type StewardCoreRepairSchema,
  sha256,
  splitStewardMigrationStatements,
  stewardCatalogKey,
} from "../src/steward-core-repair-sources";

type CatalogDefinitionChange = {
  kind: string;
  objectName: string;
  before: string[];
  after: string[];
};

type CatalogEnvelope = {
  keyCount: number;
  keys?: Array<{ kind: string; objectName: string }>;
  beforeHash: string;
  afterHash: string;
  deltaHash: string;
};

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required to generate the real-Postgres repair manifest");
}

const migrationsFolder = new URL("../drizzle", import.meta.url).pathname;
const outputPath = new URL("../src/steward-core-repair-catalog.json", import.meta.url).pathname;

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
      throw new Error(`${label} failed at statement ${index + 1}/${statements.length}`, {
        cause: error,
      });
    }
  }
}

function diffCatalog(
  before: StewardCatalogRecord[],
  after: StewardCatalogRecord[],
): CatalogDefinitionChange[] {
  const beforeMap = mapStewardCatalog(before);
  const afterMap = mapStewardCatalog(after);
  const keys = [...new Set([...beforeMap.keys(), ...afterMap.keys()])].sort();
  const changes: CatalogDefinitionChange[] = [];
  for (const key of keys) {
    const beforeRecords = beforeMap.get(key) ?? [];
    const afterRecords = afterMap.get(key) ?? [];
    const beforeDefinitions = beforeRecords.map((record) => record.definition);
    const afterDefinitions = afterRecords.map((record) => record.definition);
    if (JSON.stringify(beforeDefinitions) === JSON.stringify(afterDefinitions)) continue;
    const record = afterRecords[0] ?? beforeRecords[0];
    if (!record) throw new Error(`catalog records vanished for key ${key}`);
    changes.push({
      kind: record.kind,
      objectName: record.objectName,
      before: beforeDefinitions,
      after: afterDefinitions,
    });
  }
  return changes;
}

function catalogEnvelope(
  changes: CatalogDefinitionChange[],
  includeKeys: boolean,
): CatalogEnvelope {
  const phase = (name: "before" | "after") =>
    changes.map((change) => ({
      kind: change.kind,
      objectName: change.objectName,
      definitions: change[name],
    }));
  return {
    keyCount: changes.length,
    ...(includeKeys ? { keys: changes.map(({ kind, objectName }) => ({ kind, objectName })) } : {}),
    beforeHash: sha256(JSON.stringify(phase("before"))),
    afterHash: sha256(JSON.stringify(phase("after"))),
    deltaHash: sha256(JSON.stringify(changes)),
  };
}

function semanticFinalCounts(changes: CatalogDefinitionChange[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const change of changes) {
    const definitions = change.after.filter(
      (definition) => !(change.kind === "constraint" && definition.startsWith("n|")),
    );
    counts[change.kind] = (counts[change.kind] ?? 0) + definitions.length;
  }
  return counts;
}

async function buildSchemaManifest(
  admin: ReturnType<typeof postgres>,
  originalUrl: URL,
  schema: StewardCoreRepairSchema,
) {
  const database = `steward_core_repair_${schema}_${randomUUID().replaceAll("-", "")}`;
  await admin.unsafe(`CREATE DATABASE ${quoteStewardCoreRepairIdentifier(database)}`);

  const targetUrl = new URL(originalUrl);
  targetUrl.pathname = `/${database}`;
  const searchPath = schema === "public" ? "public,pg_catalog" : `${schema},public,pg_catalog`;
  targetUrl.searchParams.set("options", `-c search_path=${searchPath}`);
  const client = postgres(targetUrl.toString(), { max: 1, prepare: false });

  try {
    if (schema !== "public") {
      await client.unsafe(`CREATE SCHEMA ${quoteStewardCoreRepairIdentifier(schema)}`);
    }

    const historicalFiles = readdirSync(migrationsFolder)
      .filter((file) => /^\d{4}_.+\.sql$/.test(file))
      .filter((file) => Number(file.slice(0, 4)) <= 81)
      .sort();
    for (const file of historicalFiles) {
      const source = renderHistoricalFixture(
        readFileSync(`${migrationsFolder}/${file}`, "utf8"),
        schema,
      );
      await applySource(client as unknown as StewardCoreRepairExecutor, source, file);
    }

    const before0083 = await queryStewardCatalog(
      client as unknown as StewardCoreRepairExecutor,
      schema,
    );
    const source0083 = readFileSync(
      `${migrationsFolder}/0083_provider_approval_quorum.sql`,
      "utf8",
    );
    await applySource(
      client as unknown as StewardCoreRepairExecutor,
      source0083,
      "0083_provider_approval_quorum",
    );
    const discontinuity = await queryStewardCatalog(
      client as unknown as StewardCoreRepairExecutor,
      schema,
    );

    const sources = loadStewardCoreRepairSources(schema);
    let after0082: StewardCatalogRecord[] = [];
    await client.begin(async (transaction) => {
      const migration0082 = sources.find(
        (source) => source.tag === "0082_execution_authorization_v2",
      );
      if (!migration0082) throw new Error("0082 source is missing from the repair bundle");
      await applySource(
        transaction as unknown as StewardCoreRepairExecutor,
        migration0082.rendered,
        migration0082.tag,
      );
      after0082 = await queryStewardCatalog(
        transaction as unknown as StewardCoreRepairExecutor,
        schema,
      );
      for (const source of sources) {
        if (source.action === "verified_existing" || source === migration0082) continue;
        await applySource(
          transaction as unknown as StewardCoreRepairExecutor,
          source.rendered,
          source.tag,
        );
      }
    });
    const repaired = await queryStewardCatalog(
      client as unknown as StewardCoreRepairExecutor,
      schema,
    );

    const existing0083Definitions = diffCatalog(before0083, discontinuity);
    const changes0082Definitions = diffCatalog(discontinuity, after0082);
    const changes0084To0110Definitions = diffCatalog(after0082, repaired);
    const changesDefinitions = diffCatalog(discontinuity, repaired);
    const existing0083 = catalogEnvelope(existing0083Definitions, true);
    const changes0082 = catalogEnvelope(changes0082Definitions, false);
    const changes0084To0110 = catalogEnvelope(changes0084To0110Definitions, false);
    const changes = catalogEnvelope(changesDefinitions, true);
    const changedKeys = new Set(changesDefinitions.map((record) => stewardCatalogKey(record)));
    if (changedKeys.size !== changesDefinitions.length) {
      throw new Error(`${schema} repair manifest contains duplicate changed catalog keys`);
    }

    const serverVersion =
      await client.unsafe<{ server_version_num: string }[]>("SHOW server_version_num");
    return {
      serverVersionNum: serverVersion[0]?.server_version_num ?? "unknown",
      existing0083,
      changes0082,
      changes0084To0110: {
        ...changes0084To0110,
        semanticFinalCounts: semanticFinalCounts(changes0084To0110Definitions),
      },
      changes,
    };
  } finally {
    await client.end({ timeout: 5 });
    await admin.unsafe(
      `DROP DATABASE IF EXISTS ${quoteStewardCoreRepairIdentifier(database)} WITH (FORCE)`,
    );
  }
}

const originalUrl = new URL(databaseUrl);
const maintenanceUrl = new URL(originalUrl);
maintenanceUrl.pathname = "/postgres";
maintenanceUrl.searchParams.delete("options");
const admin = postgres(maintenanceUrl.toString(), { max: 1, prepare: false });

try {
  const publicManifest = await buildSchemaManifest(admin, originalUrl, "public");
  const stewardManifest = await buildSchemaManifest(admin, originalUrl, "steward");
  const manifest = {
    manifestVersion: 1,
    repairVersion: STEWARD_CORE_REPAIR_VERSION,
    sourceHead: STEWARD_CORE_REPAIR_SOURCE_HEAD,
    schemas: {
      public: publicManifest,
      steward: stewardManifest,
    },
  };
  writeFileSync(outputPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(
    `[steward-core-repair] wrote ${outputPath} (` +
      `public ${publicManifest.changes.keyCount} changes, ` +
      `steward ${stewardManifest.changes.keyCount} changes)`,
  );
} finally {
  await admin.end({ timeout: 5 });
}
