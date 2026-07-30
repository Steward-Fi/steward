import { afterEach, describe, expect, test } from "bun:test";
import { createPGLiteDb } from "@stwd/db/pglite";
import { DevMeasurementKeyProvider, SealedState } from "@stwd/sealed-state";

const clients: Array<{ close(): Promise<void> }> = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
});

describe("embedded sealed PGLite production path", () => {
  test("persists and restores state only through an authenticated envelope", async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const first = await createPGLiteDb();
    clients.push(first.client);
    await first.client.exec("CREATE TABLE sealed_probe (value text NOT NULL)");
    await first.client.exec("INSERT INTO sealed_probe VALUES ('private memory')");

    const dump = await first.client.dumpDataDir("gzip");
    const measurement = { imageDigest: "test-image", configHash: "test-compose" };
    const sealed = new SealedState(
      new DevMeasurementKeyProvider("development-secret-only", "test"),
    );
    const envelope = await sealed.seal(
      new Uint8Array(await dump.arrayBuffer()),
      measurement,
      "embedded-agent-state",
    );
    expect(JSON.stringify(envelope)).not.toContain("private memory");

    const restoredBytes = await sealed.unseal(envelope, measurement);
    const restored = await createPGLiteDb(
      undefined,
      new Blob([
        restoredBytes.buffer.slice(
          restoredBytes.byteOffset,
          restoredBytes.byteOffset + restoredBytes.byteLength,
        ) as ArrayBuffer,
      ]),
    );
    clients.push(restored.client);
    const result = await restored.client.query<{ value: string }>("SELECT value FROM sealed_probe");
    expect(result.rows[0]?.value).toBe("private memory");
  }, 30_000);
});
