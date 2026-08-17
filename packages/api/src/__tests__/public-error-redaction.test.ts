import { describe, expect, it } from "bun:test";
import { PublicApiError, sanitizePublicError } from "../services/public-error";

describe("public error redaction", () => {
  it("returns only messages selected by the closed typed table", () => {
    expect(sanitizePublicError(new PublicApiError("resource_not_found"))).toBe(
      "Resource not found",
    );
  });

  it("never substring-allows credential-bearing dependency text", () => {
    const canary = "SUPER_SECRET_PROVIDER_TOKEN";
    const raw = new Error(
      `Key arn:aws:kms:us-east-1:123456789012:key/example not found at https://example.test/${canary}`,
    );
    const message = sanitizePublicError(raw);
    expect(message).toBe("Internal server error");
    expect(message).not.toContain(canary);
    expect(message).not.toContain("arn:aws:kms");
  });
});
