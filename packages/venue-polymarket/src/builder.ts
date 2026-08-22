import { runtimeEnvironmentSnapshot } from "@stwd/shared/runtime-env";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Builder attribution = THE REVENUE RAIL.
//
// Polymarket has a builder program: attach a builder config so the platform
// earns a fee/attribution on routed orders. This mirrors the HL builder-code
// fee pattern (venue-hyperliquid's `builder` on the order action).
//
// DESIGN: builder attribution is CONFIG (env/args), DEFAULTING TO OFF/0, so it
// is INERT until explicitly enabled. The package wires the seam; the operator
// flips it on with a real builder Safe + signing-server.
//
// The Polymarket builder SDK (@polymarket/builder-signing-sdk) takes a
// `remoteBuilderConfig` pointing at a signing server that holds the builder key
// and stamps attribution headers. We construct that lazily and only when
// enabled, so nothing reaches out at import/test time.
// ---------------------------------------------------------------------------

export const builderConfigInputSchema = z
  .object({
    /** Master switch. Defaults OFF — inert until an operator enables it. */
    enabled: z.boolean().default(false),
    /** Builder fee-collecting Safe address (the receiver). Config, not hardcoded. */
    receiver: z
      .string()
      .regex(/^0x[0-9a-fA-F]{40}$/, "builder receiver must be a 0x-address")
      .optional(),
    /** Builder fee in basis points. Defaults 0. */
    feeBps: z.number().int().min(0).max(1000).default(0),
    /** Remote signing-server URL that holds the builder key + stamps attribution. */
    signingServerUrl: z.string().url().optional(),
    /** Auth token for the signing server. */
    signingServerToken: z.string().trim().min(1).optional(),
  })
  .superRefine((config, ctx) => {
    const configuredWhileDisabled =
      !config.enabled &&
      (config.receiver !== undefined ||
        config.feeBps > 0 ||
        config.signingServerUrl !== undefined ||
        config.signingServerToken !== undefined);
    if (configuredWhileDisabled) {
      ctx.addIssue({
        code: "custom",
        message:
          "builder settings require enabled=true; partial disabled configuration is rejected",
      });
      return;
    }
    if (!config.enabled) return;
    if (!config.receiver) {
      ctx.addIssue({
        code: "custom",
        path: ["receiver"],
        message: "enabled builder requires receiver",
      });
    }
    if (!config.signingServerUrl) {
      ctx.addIssue({
        code: "custom",
        path: ["signingServerUrl"],
        message: "enabled builder requires signing server URL",
      });
    } else {
      const url = new URL(config.signingServerUrl);
      const loopback =
        url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
      if (url.username || url.password) {
        ctx.addIssue({
          code: "custom",
          path: ["signingServerUrl"],
          message: "builder signing server URL must not contain credentials",
        });
      }
      if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
        ctx.addIssue({
          code: "custom",
          path: ["signingServerUrl"],
          message: "builder signing server URL must use HTTPS (HTTP is allowed only on loopback)",
        });
      }
    }
    if (!config.signingServerToken) {
      ctx.addIssue({
        code: "custom",
        path: ["signingServerToken"],
        message: "enabled builder requires signing server token",
      });
    }
  });
export type BuilderConfigInput = z.input<typeof builderConfigInputSchema>;
export type ResolvedBuilderConfig = z.infer<typeof builderConfigInputSchema>;

/**
 * Resolve builder config from explicit input, falling back to env. Defaults to
 * DISABLED with feeBps 0. NEVER throws on missing config — just stays off.
 *
 *   POLYMARKET_BUILDER_ENABLED=true
 *   POLYMARKET_BUILDER_RECEIVER=0x...
 *   POLYMARKET_BUILDER_FEE_BPS=10
 *   POLYMARKET_SIGNING_SERVER_URL=https://...
 *   POLYMARKET_SIGNING_SERVER_TOKEN=...
 */
export function resolveBuilderConfig(input?: BuilderConfigInput): ResolvedBuilderConfig {
  if (input) return builderConfigInputSchema.parse(input);

  const env = runtimeEnvironmentSnapshot();
  const envEnabled = env.POLYMARKET_BUILDER_ENABLED === "true";
  const envFeeRaw = env.POLYMARKET_BUILDER_FEE_BPS;
  return builderConfigInputSchema.parse({
    enabled: envEnabled,
    receiver: env.POLYMARKET_BUILDER_RECEIVER || undefined,
    feeBps: envFeeRaw !== undefined && envFeeRaw !== "" ? Number(envFeeRaw) : 0,
    signingServerUrl: env.POLYMARKET_SIGNING_SERVER_URL || undefined,
    signingServerToken: env.POLYMARKET_SIGNING_SERVER_TOKEN || undefined,
  });
}

export function isBuilderEnabled(config: ResolvedBuilderConfig): boolean {
  return config.enabled;
}

/**
 * Lazily build the @polymarket/builder-signing-sdk BuilderConfig, or return null
 * when disabled. Returns null (not throws) when off so the clob-client is simply
 * constructed without builder attribution.
 */
export async function createPolymarketBuilderConfig(
  config: ResolvedBuilderConfig,
): Promise<unknown | null> {
  if (!isBuilderEnabled(config)) return null;

  const { BuilderConfig } = await import("@polymarket/builder-signing-sdk");
  return new BuilderConfig({
    remoteBuilderConfig: {
      url: signEndpointUrl(config.signingServerUrl),
      token: config.signingServerToken,
    },
  });
}

/**
 * Normalize the signing-server base URL to the `/sign` endpoint. Accepts either
 * a bare base (`https://host`) or one already ending in `/sign`, so an operator
 * setting POLYMARKET_SIGNING_SERVER_URL to the host root still hits the right
 * route (matches matchr's `BASE + '/sign'` convention). Trailing slashes ok.
 */
export function signEndpointUrl(base: string | undefined): string {
  const trimmed = (base ?? "").trim();
  if (trimmed === "") return "/sign";
  // Parse so query strings / fragments are preserved and the /sign check looks
  // at the PATH only (e.g. `https://h/sign?env=prod` must not become `.../sign?env=prod/sign`).
  try {
    const u = new URL(trimmed);
    const path = stripTrailingSlashes(u.pathname);
    u.pathname = /\/sign$/.test(path) ? path : `${path}/sign`;
    return u.toString();
  } catch {
    // Not an absolute URL (relative path/host fragment) — fall back to string handling.
    const noTrailing = stripTrailingSlashes(trimmed);
    return /\/sign$/.test(noTrailing) ? noTrailing : `${noTrailing}/sign`;
  }
}

function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return end === value.length ? value : value.slice(0, end);
}
