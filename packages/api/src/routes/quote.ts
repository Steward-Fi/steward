import {
  type AttestationProvider,
  createDstackTdxProvider,
  createNoopDevProvider,
} from "@stwd/attestation";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

export const quoteRoutes = new Hono<{ Variables: AppVariables }>();

quoteRoutes.get("/", async (c) => {
  const provider = createConfiguredAttestationProvider();
  const nonce = c.req.query("nonce") ?? crypto.randomUUID();
  const quote = await provider.generateQuote({ nonce });
  return c.json(quote, quote.verified ? 200 : 503);
});

export function createConfiguredAttestationProvider(): AttestationProvider {
  const provider = process.env.STEWARD_ATTESTATION_PROVIDER ?? "noop-dev";
  switch (provider) {
    case "dstack-tdx":
      return createDstackTdxProvider();
    case "noop-dev":
      return createNoopDevProvider();
    default:
      throw new Error(`Unsupported STEWARD_ATTESTATION_PROVIDER: ${provider}`);
  }
}
