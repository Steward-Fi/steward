import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { validateAgentCardApiUrl } from "../services/agent-card-url";
import { normalizeGasSponsorshipConfig } from "../services/gas-sponsorship";
import { normalizeSamlSsoUpdate } from "../services/saml-sso-config";

const enabledWebhookPolicy = {
  STEWARD_ALLOW_INSECURE_WEBHOOK_URLS: "true",
  STEWARD_ALLOW_PRIVATE_WEBHOOK_NETWORKS: "true",
};

describe("webhook policy scope", () => {
  it("does not authorize private SAML, gas-provider, or ERC-8004 destinations", async () => {
    await withRuntimeEnvironment(enabledWebhookPolicy, async () => {
      const saml = normalizeSamlSsoUpdate("tenant-a", {
        idpEntityId: "https://idp.example.test/entity",
        idpSsoUrl: "https://10.0.0.1/sso",
        idpCertPems: [
          `-----BEGIN CERTIFICATE-----\n${"A".repeat(256)}\n-----END CERTIFICATE-----`,
        ],
      });
      expect(saml).toBe("idpSsoUrl must be a public https URL");

      const gas = normalizeGasSponsorshipConfig({
        provider: "custom_evm_paymaster",
        mode: "erc4337",
        paymasterUrl: "https://10.0.0.1/paymaster",
      });
      expect(gas).toBe(
        "paymasterUrl must be a public https URL (url host must be public)",
      );

      expect(await validateAgentCardApiUrl("https://10.0.0.1/agent-card")).toBe(
        "apiUrl url host must be public",
      );
    });
  });
});
