import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { GitHubAppInstallationTokenIssuer } from "../github-app-issuer";

const privateKeyPem = generateKeyPairSync("rsa", { modulusLength: 2048 })
  .privateKey.export({ format: "pem", type: "pkcs8" })
  .toString();

const request = {
  appId: "123",
  installationId: "456",
  privateKeyPem,
  resource: { repositories: ["steward"], permissions: { contents: "read" as const } },
  ttlSeconds: 3600,
};

describe("GitHub App upstream issuer transport", () => {
  test("bounds declared and streamed token responses before JSON parsing", async () => {
    for (const response of [
      new Response("{}", { headers: { "content-length": "1048577" } }),
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(1024 * 1024));
            controller.enqueue(new Uint8Array([1]));
            controller.close();
          },
        }),
      ),
    ]) {
      const issuer = new GitHubAppInstallationTokenIssuer((async () => response) as typeof fetch);
      await expect(issuer.issue(request)).rejects.toThrow("exceeded maximum size");
    }
  });

  test("applies deadlines without exposing upstream response bodies", async () => {
    let signal: AbortSignal | undefined;
    const canary = "upstream-secret-canary";
    const issuer = new GitHubAppInstallationTokenIssuer((async (_url, init) => {
      signal = init?.signal as AbortSignal;
      return new Response(canary, { status: 502 });
    }) as typeof fetch);
    await expect(issuer.issue(request)).rejects.not.toThrow(canary);
    expect(signal).toBeInstanceOf(AbortSignal);
  });
});
