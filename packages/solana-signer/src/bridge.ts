// Loopback HTTP bridge: the out-of-process face of the Steward Solana signer.
//
// Consumers that spawn their own process (the AgentNet MCP stdio server via its
// remote-wallet hook) cannot hold the in-process signer object, so they speak
// this three-endpoint protocol over the operator's loopback instead:
//
//   GET  /pubkey            -> { "address": "<base58>" }
//   POST /sign-transaction  { "transaction": "<base64>", "to"?, "value"? }
//                           -> { "transaction": "<base64 signed>" }
//   POST /sign-message      -> 501 always. Steward signs transactions under
//                              policy, not raw messages, so the endpoint fails
//                              closed and message-derived features stay off.
//
// Loopback is a machine-wide surface: ANY local process can connect to a
// 127.0.0.1 port, so by default every request must present a shared secret in
// the x-steward-bridge-token header. The token comes from the
// STEWARD_SIGNER_BRIDGE_TOKEN env var when set (the same var the consumer
// process reads to send the header), otherwise a fresh random token is
// generated per session and exposed as `token` on the returned bridge. A
// missing or wrong header is 401 before the signer is touched. There is no
// unauthenticated mode: browser CSRF and unrelated local processes can reach
// loopback ports too.
//
// Policy refusals map to JSON errors with the refusal text and kind, so the
// remote side can print WHY the vault said no instead of a bare status code.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { StewardSignerError, type StewardSolanaSigner, toSignerError } from "./steward-signer";

/** Header every bridge request must carry (unless the bridge runs open). */
export const BRIDGE_TOKEN_HEADER = "x-steward-bridge-token";

/** Env var supplying the shared secret on BOTH sides of the bridge. */
export const BRIDGE_TOKEN_ENV = "STEWARD_SIGNER_BRIDGE_TOKEN";

/** Enough for Solana's transaction limit plus JSON/hints, while bounding RAM. */
export const BRIDGE_MAX_BODY_BYTES = 16 * 1024;
export const BRIDGE_MIN_TOKEN_BYTES = 32;

export interface SignerBridgeOptions {
  /** Bind host. Loopback by default; never expose this beyond the machine. */
  host?: string;
  /** 0 (default) picks an ephemeral port; read the final one from `url`. */
  port?: number;
  /** Shared secret required in the x-steward-bridge-token header of every
   *  request. Omitted: STEWARD_SIGNER_BRIDGE_TOKEN from the env when set,
   *  else a fresh random token per session (read it from the returned
   *  bridge's `token`). Must contain at least 32 UTF-8 bytes. */
  token?: string;
}

export interface SignerBridge {
  url: string;
  /** The armed shared secret. */
  token: string;
  server: Server;
  close(): Promise<void>;
}

/** Constant-time header check; hashing first keeps lengths equal. */
function tokenMatches(presented: string | string[] | undefined, expected: string): boolean {
  if (typeof presented !== "string") return false;
  return timingSafeEqual(
    createHash("sha256").update(presented).digest(),
    createHash("sha256").update(expected).digest(),
  );
}

function statusFor(kind: StewardSignerError["kind"]): number {
  switch (kind) {
    case "policy_rejected":
      return 403;
    case "pending_approval":
      return 409;
    case "auth":
      return 401;
    default:
      return 502;
  }
}

function respond(res: ServerResponse, status: number, body: object): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(payload);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const declaredLength = Number(req.headers["content-length"]);
  if (
    req.headers["content-length"] !== undefined &&
    (!Number.isSafeInteger(declaredLength) ||
      declaredLength < 0 ||
      declaredLength > BRIDGE_MAX_BODY_BYTES)
  ) {
    throw new PayloadTooLargeError();
  }
  const chunks: Buffer[] = [];
  let received = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    received += bytes.length;
    if (received > BRIDGE_MAX_BODY_BYTES) throw new PayloadTooLargeError();
    chunks.push(bytes);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("request body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

class PayloadTooLargeError extends Error {}

function assertLoopbackHost(host: string): void {
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new StewardSignerError(
      "api",
      `signer bridge host must be a loopback IP literal (127.0.0.1 or ::1), got ${host}`,
    );
  }
}

export async function startSignerBridge(
  signer: StewardSolanaSigner,
  options: SignerBridgeOptions = {},
): Promise<SignerBridge> {
  const host = options.host ?? "127.0.0.1";
  assertLoopbackHost(host);
  const token =
    options.token === undefined
      ? process.env[BRIDGE_TOKEN_ENV] || randomBytes(32).toString("hex")
      : options.token;
  if (Buffer.byteLength(token, "utf8") < BRIDGE_MIN_TOKEN_BYTES) {
    throw new StewardSignerError(
      "api",
      `signer bridge token must contain at least ${BRIDGE_MIN_TOKEN_BYTES} bytes`,
    );
  }

  let signing = false;

  const server = createServer((req, res) => {
    void handle(req, res);
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Auth before routing: an unauthenticated caller learns nothing and the
    // signer is never touched.
    if (!tokenMatches(req.headers[BRIDGE_TOKEN_HEADER], token)) {
      respond(res, 401, {
        error:
          `missing or wrong ${BRIDGE_TOKEN_HEADER} header; this bridge only answers ` +
          "callers holding its session's shared secret",
      });
      return;
    }
    try {
      if (req.method === "GET" && req.url === "/pubkey") {
        respond(res, 200, { address: signer.address });
        return;
      }
      if (req.method === "POST" && req.url === "/sign-transaction") {
        if (signing) {
          respond(res, 429, { error: "another signing request is already in progress" });
          return;
        }
        if (!req.headers["content-type"]?.toLowerCase().startsWith("application/json")) {
          respond(res, 415, { error: "content-type must be application/json" });
          return;
        }
        // Reserve the single signing slot before the first await. Otherwise two
        // slow/chunked bodies can both observe `signing === false` and race into
        // the vault together after parsing.
        signing = true;
        try {
          let body: Record<string, unknown>;
          try {
            body = await readJson(req);
          } catch (err) {
            if (err instanceof PayloadTooLargeError) {
              respond(res, 413, { error: `request body exceeds ${BRIDGE_MAX_BODY_BYTES} bytes` });
              return;
            }
            respond(res, 400, { error: err instanceof Error ? err.message : "invalid JSON body" });
            return;
          }
          if (typeof body.transaction !== "string" || body.transaction.length === 0) {
            respond(res, 400, {
              error: "'transaction' (base64 serialized Solana tx) is required",
            });
            return;
          }
          const transaction = await signer.signSerializedTransaction(body.transaction, {
            to: typeof body.to === "string" ? body.to : undefined,
            value: typeof body.value === "string" ? body.value : undefined,
          });
          respond(res, 200, { transaction });
        } finally {
          signing = false;
        }
        return;
      }
      if (req.method === "POST" && req.url === "/sign-message") {
        respond(res, 501, {
          error:
            "Steward signs transactions under policy, not raw messages; message signing stays closed",
        });
        return;
      }
      respond(res, 404, { error: "not found" });
    } catch (err) {
      const mapped = toSignerError(err);
      respond(res, statusFor(mapped.kind), {
        error: mapped.kind === "api" ? "Steward signing service failed" : mapped.message,
        kind: mapped.kind,
        ...(mapped.txId ? { txId: mapped.txId } : {}),
      });
    }
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, host, resolve);
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 5_000;
  const bound = server.address();
  if (bound === null || typeof bound === "string") {
    throw new StewardSignerError("api", "signer bridge failed to bind a TCP port");
  }
  return {
    url: `http://${host.includes(":") ? `[${host}]` : host}:${bound.port}`,
    token,
    server,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
