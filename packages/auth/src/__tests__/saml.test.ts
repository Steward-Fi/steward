import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("SAML ACS verifier hardening", () => {
  it("pins node-saml to signed assertions, signed responses, audience, ACS, and InResponseTo", () => {
    const source = read("packages/auth/src/saml.ts");

    expect(source).toContain("wantAssertionsSigned: true");
    expect(source).toContain("wantAuthnResponseSigned: true");
    expect(source).toContain("audience: input.spEntityId");
    expect(source).toContain("callbackUrl: input.acsUrl");
    expect(source).toContain("idpIssuer: input.idpEntityId");
    expect(source).toContain("ValidateInResponseTo.always");
    expect(source).toContain("cacheProvider: new SingleUseInResponseToCache");
    expect(source).toContain('signatureAlgorithm: "sha256"');
    expect(source).toContain('digestAlgorithm: "sha256"');
    expect(source).toContain("SAML assertion ID is required for replay protection");
    expect(source).toContain("export async function buildSamlAuthorizeUrl");
    expect(source).toContain("generateUniqueId: () => input.requestId");
  });

  it("does not parse assertion attributes from raw unvalidated XML", () => {
    const source = read("packages/auth/src/saml.ts");

    expect(source).toContain(
      "saml.validatePostResponseAsync({ SAMLResponse: input.samlResponse })",
    );
    expect(source).toContain("const profile = result.profile");
    expect(source).not.toContain("parseString");
    expect(source).not.toContain("DOMParser");
    expect(source).not.toContain("getSamlResponseXml()");
    expect(source).not.toContain("getAssertionXml()");
  });
});
