import { expect, test } from "bun:test";
import { resolve } from "node:path";

test("the production StewardClient replaces bearer authority and clears it before failure", async () => {
  const apiPath = resolve(import.meta.dir, "api.ts");
  const sdkPath = resolve(import.meta.dir, "../../../packages/sdk/src/index.ts");
  const script = `
    Bun.plugin({
      name: "workspace-sdk-source",
      setup(build) {
        build.onResolve({ filter: /^@stwd\\/sdk$/ }, () => ({ path: ${JSON.stringify(sdkPath)} }));
      },
    });
    const { clearAuthToken, setAuthToken, setTenantId, steward } = await import(${JSON.stringify(apiPath)});
    const requests = [];
    let responseStatus = 200;
    globalThis.fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      requests.push({
        authorization: headers.get("authorization"),
        tenantId: headers.get("x-steward-tenant"),
        url: String(input),
      });
      return new Response(JSON.stringify(
        responseStatus === 200
          ? { ok: true, data: [] }
          : { ok: false, error: "signed-out request rejected" },
      ), {
        status: responseStatus,
        headers: { "content-type": "application/json" },
      });
    };
    setTenantId("tenant-auth-transition");
    setAuthToken("session-a");
    await steward.listAgents();
    setAuthToken("session-b");
    await steward.listAgents();
    responseStatus = 401;
    clearAuthToken();
    try { await steward.listAgents(); } catch {}
    console.log("AUTH_TRANSITION_RESULT=" + JSON.stringify(requests));
  `;

  const child = Bun.spawn([process.execPath, "-e", script], {
    cwd: resolve(import.meta.dir, "../../.."),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  expect(exitCode, stderr).toBe(0);
  const resultLine = stdout.split("\n").find((line) => line.startsWith("AUTH_TRANSITION_RESULT="));
  expect(resultLine).toBeDefined();
  const requests = JSON.parse(
    resultLine?.slice("AUTH_TRANSITION_RESULT=".length) ?? "[]",
  ) as Array<{
    authorization: string | null;
    tenantId: string | null;
    url: string;
  }>;

  expect(requests.map(({ authorization }) => authorization)).toEqual([
    "Bearer session-a",
    "Bearer session-b",
    null,
  ]);
  expect(requests[2]?.tenantId).toBe("tenant-auth-transition");
  expect(requests.every(({ url }) => url.includes("/agents?limit="))).toBe(true);
});
