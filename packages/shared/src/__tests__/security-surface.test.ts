import { describe, expect, test } from "bun:test";
import {
  SECURITY_SURFACE_OPERATIONS,
  SECURITY_SURFACE_ROUTES,
  SECURITY_SURFACE_VAULT_METHODS,
} from "../security-surface.js";

const read = async (path: string) => Bun.file(new URL(path, import.meta.url)).text();

const SIGN_CAPABLE_OR_EXPORT = /^(sign[A-Z].*|prepareMoneroTransfer|relayMoneroTransfer|exportPrivateKey)$/;
const ROUTE_CALL =
  /\b(?:vault|getVault\(\))\.(sign[A-Z]\w*|prepareMoneroTransfer|relayMoneroTransfer|exportPrivateKey)\b/g;

function routeRegistrationRegex(method: string, path: string): RegExp {
  return new RegExp(`\\.${method.toLowerCase()}\\(\\s*["'\`]${escapeRegex(path)}["'\`]`);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function lineNumber(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

describe("security surface inventory", () => {
  test("classifies every sign-capable Vault method and break-glass export", async () => {
    const source = await read("../../../vault/src/vault.ts");
    const actual = [...source.matchAll(/^\s+async\s+(\w+)\(/gm)]
      .map((match) => match[1])
      .filter((method) => SIGN_CAPABLE_OR_EXPORT.test(method))
      .sort();

    expect(SECURITY_SURFACE_VAULT_METHODS).toEqual(actual);
  });

  test("classifies every route call to a sensitive Vault method", async () => {
    const routeFiles = [
      ...new Bun.Glob("*.ts").scanSync({
        cwd: new URL("../../../api/src/routes/", import.meta.url).pathname,
      }),
    ].map((file) => `packages/api/src/routes/${file}`);

    const failures: string[] = [];
    for (const file of routeFiles) {
      const source = await read(`../../../${file.replace("packages/", "")}`);
      for (const match of source.matchAll(ROUTE_CALL)) {
        const method = match[1];
        const classified = SECURITY_SURFACE_OPERATIONS.some(
          (operation) =>
            operation.vaultMethods.includes(method) &&
            operation.routes.some((route) => route.file === file),
        );
        if (!classified) {
          failures.push(`${file}:${lineNumber(source, match.index ?? 0)} calls ${method}`);
        }
      }
    }

    expect(failures).toEqual([]);
  });

  test("keeps classified API routes grounded in actual route registrations", async () => {
    const missing: string[] = [];
    for (const route of SECURITY_SURFACE_ROUTES) {
      if (route.method === "HANDLER") continue;
      if (!route.file.startsWith("packages/api/")) continue;

      const source = await read(`../../../${route.file.replace("packages/", "")}`);
      if (!routeRegistrationRegex(route.method, route.path).test(source)) {
        missing.push(`${route.file} ${route.method} ${route.path}`);
      }
    }

    expect(missing).toEqual([]);
  });

  test("classifies proxy credential injection against the actual decrypt path", async () => {
    const proxySource = await read("../../../proxy/src/handlers/proxy.ts");
    const secretVaultSource = await read("../../../vault/src/secret-vault.ts");
    const credentialOperation = SECURITY_SURFACE_OPERATIONS.find(
      (operation) => operation.id === "credential.proxy.inject_http",
    );

    expect(credentialOperation?.vaultMethods).toContain("SecretVault.decryptSecret");
    expect(credentialOperation?.routes.some((route) => route.file === "packages/proxy/src/handlers/proxy.ts")).toBe(
      true,
    );
    expect(secretVaultSource).toContain("async decryptSecret(");
    expect(proxySource).toContain("credential = await decryptSecret(");
    expect(proxySource).toContain("await recordAudit({");
  });
});
