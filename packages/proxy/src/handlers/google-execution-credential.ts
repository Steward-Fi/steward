import { randomUUID } from "node:crypto";
import {
  and,
  eq,
  getDb,
  inArray,
  providerAccounts,
  providerGoogleCredentialLifecycles,
  secrets,
  withTenantAuditedTransaction,
} from "@stwd/db";
import { strictParseJson } from "@stwd/shared";
import type { SecretVault } from "@stwd/vault";

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const MAX_RESPONSE_BYTES = 1024 * 1024;

type DbBase = ReturnType<typeof getDb>;
type DbExecutor = DbBase | Parameters<Parameters<DbBase["transaction"]>[0]>[0];

type GoogleCredentialEnvelope = {
  schemaVersion: "steward.provider-google.credential.v1";
  refreshToken: string;
  scopesGranted: string[];
};

type GoogleRefreshResponse = {
  access_token?: unknown;
  refresh_token?: unknown;
  scope?: unknown;
  token_type?: unknown;
  expires_in?: unknown;
  error?: unknown;
};

type GoogleTokenForwarder = (body: string) => Promise<Response>;

async function defaultGoogleTokenForwarder(body: string): Promise<Response> {
  return fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
}

let googleTokenForwarder: GoogleTokenForwarder = defaultGoogleTokenForwarder;

export function __setGoogleExecutionTokenForwarderForTests(
  forwarder: GoogleTokenForwarder | null,
): void {
  googleTokenForwarder = forwarder ?? defaultGoogleTokenForwarder;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_RESPONSE_BYTES) {
      await response.body?.cancel().catch(() => {});
      throw new Error("Google token response exceeded maximum size");
    }
  }
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error("Google token response exceeded maximum size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return strictParseJson(new TextDecoder().decode(bytes));
}

function parseEnvelope(value: string): GoogleCredentialEnvelope {
  const parsed = strictParseJson(value) as Record<string, unknown>;
  if (
    parsed.schemaVersion !== "steward.provider-google.credential.v1" ||
    typeof parsed.refreshToken !== "string" ||
    parsed.refreshToken.length < 1 ||
    parsed.refreshToken.length > 16_384 ||
    !Array.isArray(parsed.scopesGranted) ||
    parsed.scopesGranted.length < 1 ||
    parsed.scopesGranted.length > 64 ||
    !parsed.scopesGranted.every(
      (scope) =>
        typeof scope === "string" &&
        scope.length > 0 &&
        scope.length <= 512 &&
        /^[\x21-\x7e]+$/.test(scope),
    )
  ) {
    throw new Error("invalid Google OAuth credential envelope");
  }
  return parsed as unknown as GoogleCredentialEnvelope;
}

function validateResponse(
  raw: unknown,
  allowedScopes: readonly string[],
): asserts raw is GoogleRefreshResponse & { access_token: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("invalid Google refresh response");
  }
  const response = raw as GoogleRefreshResponse;
  if (
    typeof response.access_token !== "string" ||
    response.access_token.length < 1 ||
    response.access_token.length > 16_384 ||
    !/^[A-Za-z0-9\-._~+/]+=*$/.test(response.access_token) ||
    (response.refresh_token !== undefined &&
      (typeof response.refresh_token !== "string" ||
        response.refresh_token.length < 1 ||
        response.refresh_token.length > 16_384 ||
        !/^[A-Za-z0-9\-._~+/]+=*$/.test(response.refresh_token))) ||
    (response.token_type !== undefined &&
      (typeof response.token_type !== "string" ||
        response.token_type.toLowerCase() !== "bearer")) ||
    typeof response.expires_in !== "number" ||
    !Number.isSafeInteger(response.expires_in) ||
    response.expires_in < 300 ||
    response.expires_in > 86_400
  ) {
    throw new Error("invalid Google refresh response");
  }
  const returnedScopes =
    response.scope === undefined
      ? [...allowedScopes]
      : typeof response.scope === "string" && response.scope.length <= 32_768
        ? [...new Set(response.scope.split(/\s+/).filter(Boolean))]
        : [];
  const allow = new Set(allowedScopes);
  if (
    returnedScopes.length < 1 ||
    returnedScopes.length > 64 ||
    returnedScopes.some(
      (scope) => scope.length > 512 || !/^[\x21-\x7e]+$/.test(scope) || !allow.has(scope),
    )
  ) {
    throw new Error("Google refresh widened OAuth scope");
  }
}

async function setUnknownOutcome(input: GoogleExecutionCredentialInput, lifecycleId: string) {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    await tx
      .update(providerAccounts)
      .set({ status: "disabled", revision: input.accountRevision + 1, updatedAt: new Date() })
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.workspaceId, input.workspaceId),
          eq(providerAccounts.id, input.accountId),
          eq(providerAccounts.revision, input.accountRevision),
          eq(providerAccounts.status, "active"),
        ),
      );
    await tx
      .update(providerGoogleCredentialLifecycles)
      .set({
        state: "needs_attention",
        lastErrorCode: "REFRESH_OUTCOME_UNKNOWN",
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
          eq(providerGoogleCredentialLifecycles.id, lifecycleId),
          eq(providerGoogleCredentialLifecycles.providerAccountId, input.accountId),
        ),
      );
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "credential-proxy",
      action: "provider.google.refresh.needs_attention",
      resourceType: "provider_account",
      resourceId: input.accountId,
      metadata: { lifecycleId, workspaceId: input.workspaceId, reason: "REFRESH_OUTCOME_UNKNOWN" },
    });
  });
}

export interface GoogleExecutionCredentialInput {
  tenantId: string;
  workspaceId: string;
  accountId: string;
  accountRevision: number;
  credential: string;
  vault: SecretVault;
  clientId: string;
  clientSecret: string;
}

/** Mint a short-lived access token at the exact governed execution boundary. */
export async function mintGoogleExecutionAccessToken(
  input: GoogleExecutionCredentialInput,
): Promise<string> {
  const envelope = parseEnvelope(input.credential);
  const lifecycleId = randomUUID();
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const [account] = await tx
      .select({ id: providerAccounts.id })
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.workspaceId, input.workspaceId),
          eq(providerAccounts.id, input.accountId),
          eq(providerAccounts.revision, input.accountRevision),
          eq(providerAccounts.status, "active"),
        ),
      )
      .limit(1)
      .for("update");
    if (!account) throw new Error("Google provider account changed before token mint");
    const [active] = await tx
      .select({ id: providerGoogleCredentialLifecycles.id })
      .from(providerGoogleCredentialLifecycles)
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
          eq(providerGoogleCredentialLifecycles.providerAccountId, input.accountId),
          eq(providerGoogleCredentialLifecycles.kind, "refresh_rotation"),
          inArray(providerGoogleCredentialLifecycles.state, ["inflight", "credential_staged"]),
        ),
      )
      .limit(1);
    if (active) throw new Error("Google credential refresh is already in progress");
    await tx.insert(providerGoogleCredentialLifecycles).values({
      id: lifecycleId,
      tenantId: input.tenantId,
      workspaceId: input.workspaceId,
      providerAccountId: input.accountId,
      kind: "refresh_rotation",
      state: "inflight",
      expectedAccountRevision: input.accountRevision,
    });
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "credential-proxy",
      action: "provider.google.refresh.intent_staged",
      resourceType: "provider_google_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: { workspaceId: input.workspaceId, providerAccountId: input.accountId },
    });
  });

  let response: Response;
  try {
    response = await googleTokenForwarder(
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: envelope.refreshToken,
        client_id: input.clientId,
        client_secret: input.clientSecret,
      }).toString(),
    );
  } catch (error) {
    await setUnknownOutcome(input, lifecycleId);
    throw error;
  }

  let raw: unknown;
  try {
    raw = await readBoundedJson(response);
  } catch (error) {
    await setUnknownOutcome(input, lifecycleId);
    throw error;
  }
  if (!response.ok) {
    await setUnknownOutcome(input, lifecycleId);
    throw new Error(
      (raw as GoogleRefreshResponse | null)?.error === "invalid_grant"
        ? "Google refresh token revoked"
        : "Google refresh failed",
    );
  }

  let stagedSecretId: string | null = null;
  try {
    await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
      const tx = txRaw as DbExecutor;
      const secret = await input.vault.createSecretWithinTx(
        tx,
        input.tenantId,
        `provider-google-lifecycle:${lifecycleId}`,
        JSON.stringify({ schemaVersion: "steward.provider-google.lifecycle.v1", token: raw }),
        { description: "Encrypted transient Google OAuth recovery material" },
      );
      stagedSecretId = secret.id;
      const [updated] = await tx
        .update(providerGoogleCredentialLifecycles)
        .set({ state: "credential_staged", credentialSecretId: secret.id, updatedAt: new Date() })
        .where(
          and(
            eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
            eq(providerGoogleCredentialLifecycles.id, lifecycleId),
            eq(providerGoogleCredentialLifecycles.state, "inflight"),
          ),
        )
        .returning({ id: providerGoogleCredentialLifecycles.id });
      if (!updated) throw new Error("Google refresh lifecycle changed before staging");
      await append({
        tenantId: input.tenantId,
        actorType: "system",
        actorId: "credential-proxy",
        action: "provider.google.refresh.credential_staged",
        resourceType: "provider_google_credential_lifecycle",
        resourceId: lifecycleId,
        metadata: { providerAccountId: input.accountId },
      });
    });
  } catch (error) {
    // The provider may have rotated the refresh token even though its response
    // could not be durably escrowed. Freeze the old authority before returning.
    await setUnknownOutcome(input, lifecycleId);
    throw error;
  }

  try {
    validateResponse(raw, envelope.scopesGranted);
  } catch (error) {
    await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
      const tx = txRaw as DbExecutor;
      await tx
        .update(providerAccounts)
        .set({ status: "disabled", revision: input.accountRevision + 1, updatedAt: new Date() })
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.workspaceId, input.workspaceId),
            eq(providerAccounts.id, input.accountId),
            eq(providerAccounts.revision, input.accountRevision),
            eq(providerAccounts.status, "active"),
          ),
        );
      await tx
        .update(providerGoogleCredentialLifecycles)
        .set({
          state: "revocation_pending",
          lastErrorCode: "INVALID_REFRESH_RESPONSE",
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
            eq(providerGoogleCredentialLifecycles.id, lifecycleId),
          ),
        );
      await append({
        tenantId: input.tenantId,
        actorType: "system",
        actorId: "credential-proxy",
        action: "provider.google.refresh.invalid_response",
        resourceType: "provider_account",
        resourceId: input.accountId,
        metadata: { lifecycleId, workspaceId: input.workspaceId },
      });
    });
    throw error;
  }

  const accountStillCurrent = await withTenantAuditedTransaction(
    input.tenantId,
    async (txRaw, append) => {
      const tx = txRaw as DbExecutor;
      const [account] = await tx
        .select({ id: providerAccounts.id })
        .from(providerAccounts)
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.workspaceId, input.workspaceId),
            eq(providerAccounts.id, input.accountId),
            eq(providerAccounts.revision, input.accountRevision),
            eq(providerAccounts.status, "active"),
          ),
        )
        .limit(1)
        .for("update");
      if (!account) {
        await tx
          .update(providerGoogleCredentialLifecycles)
          .set({
            state: "revocation_pending",
            lastErrorCode: "ACCOUNT_REVISION_CHANGED",
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
              eq(providerGoogleCredentialLifecycles.id, lifecycleId),
              eq(providerGoogleCredentialLifecycles.state, "credential_staged"),
            ),
          );
        await append({
          tenantId: input.tenantId,
          actorType: "system",
          actorId: "credential-proxy",
          action: "provider.google.refresh.needs_attention",
          resourceType: "provider_account",
          resourceId: input.accountId,
          metadata: {
            lifecycleId,
            workspaceId: input.workspaceId,
            reason: "ACCOUNT_REVISION_CHANGED",
          },
        });
        return false;
      }

      if (raw.refresh_token === undefined) {
        const [adopted] = await tx
          .update(providerGoogleCredentialLifecycles)
          .set({ state: "adopted", credentialSecretId: null, updatedAt: new Date() })
          .where(
            and(
              eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
              eq(providerGoogleCredentialLifecycles.id, lifecycleId),
              eq(providerGoogleCredentialLifecycles.credentialSecretId, stagedSecretId as string),
              eq(providerGoogleCredentialLifecycles.state, "credential_staged"),
            ),
          )
          .returning({ id: providerGoogleCredentialLifecycles.id });
        if (!adopted) return false;
        await tx
          .delete(secrets)
          .where(
            and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, stagedSecretId as string)),
          );
      }
      await append({
        tenantId: input.tenantId,
        actorType: "system",
        actorId: "credential-proxy",
        action: "provider.google.refresh.execution_token_minted",
        resourceType: "provider_account",
        resourceId: input.accountId,
        metadata: { lifecycleId, workspaceId: input.workspaceId },
      });
      return true;
    },
  );
  if (!accountStillCurrent) {
    throw new Error("Google provider account changed during token mint");
  }

  return raw.access_token;
}
