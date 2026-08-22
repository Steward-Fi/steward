import { closeDb } from "@stwd/db";
import { app } from "../../app";
import { initRedis, shutdownRedis } from "../../middleware/redis";
import { getAuthStoreSources, initAuthStores } from "../../routes/auth";

type ReplicaRequest = {
  method: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
};

function errorChain(error: unknown): string[] {
  const messages: string[] = [];
  let current = error;
  while (current instanceof Error && messages.length < 8) {
    messages.push(`${current.name}: ${current.message}`);
    current = current.cause;
  }
  return messages;
}

const encoded = process.env.TEST_REPLICA_REQUEST;
const outputPath = process.env.TEST_REPLICA_OUTPUT;
if (!encoded || !outputPath) throw new Error("replica request configuration is required");

const request = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as ReplicaRequest;

try {
  if (!(await initRedis())) throw new Error("real Redis is required");
  await initAuthStores(false);
  if (getAuthStoreSources().mfa !== "redis") throw new Error("MFA store is not using Redis");
  app.onError((error, c) =>
    c.json(
      {
        ok: false,
        error: error.message,
        errorChain: errorChain(error),
        stack: error.stack ?? null,
      },
      500,
    ),
  );

  const response = await app.request(`http://localhost${request.path}`, {
    method: request.method,
    headers: {
      ...(request.body === undefined ? {} : { "content-type": "application/json" }),
      ...request.headers,
    },
    body: request.body === undefined ? undefined : JSON.stringify(request.body),
  });
  const text = await response.text();
  await Bun.write(
    outputPath,
    JSON.stringify({
      status: response.status,
      body: text ? JSON.parse(text) : null,
      storeSources: getAuthStoreSources(),
    }),
  );
} finally {
  await closeDb().catch(() => undefined);
  await shutdownRedis().catch(() => undefined);
}

// @stwd/auth owns a separate lazy Redis connection for revocation lines. The
// fixture is intentionally one request per process (a production replica), so
// terminate after durable output rather than retaining that singleton handle.
process.exit(0);
