import { describe, expect, it } from "bun:test";
import {
  PLAINTEXT_KEY_EXPORT_ACKNOWLEDGEMENT,
  plaintextKeyExportResponseGateError,
} from "../services/key-export-plaintext-gate";

describe("plaintext key export response gate", () => {
  it("does not require plaintext acknowledgement outside production-like environments", () => {
    expect(
      plaintextKeyExportResponseGateError(undefined, {
        NODE_ENV: "test",
      }),
    ).toBeNull();
  });

  it("rejects production plaintext exports unless the production override is enabled", () => {
    const error = plaintextKeyExportResponseGateError(undefined, {
      NODE_ENV: "production",
      STEWARD_ALLOW_PRIVATE_KEY_EXPORT: "true",
      STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT: "true",
    });

    expect(error).toContain("disabled in production");
    expect(error).toContain("STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION");
  });

  it("requires an exact per-request acknowledgement when the production override is enabled", () => {
    const env = {
      STEWARD_ENV: "prod",
      STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION: "true",
    };

    expect(
      plaintextKeyExportResponseGateError({ plaintextExportAcknowledgement: "yes" }, env),
    ).toContain("requires plaintextExportAcknowledgement");
    expect(
      plaintextKeyExportResponseGateError(
        { plaintextExportAcknowledgement: PLAINTEXT_KEY_EXPORT_ACKNOWLEDGEMENT },
        env,
      ),
    ).toBeNull();
  });
});
