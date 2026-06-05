#!/usr/bin/env bun

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const DEFAULT_PRIVY_OPENAPI_URL = "https://api.privy.io/v1/openapi.json";

type HttpMethod = "get" | "post" | "put" | "patch" | "delete";

type OpenApiOperation = {
  operationId?: string;
  tags?: string[];
};

type OpenApiDocument = {
  paths?: Record<string, Partial<Record<HttpMethod, OpenApiOperation>>>;
};

export type Endpoint = {
  method: HttpMethod;
  path: string;
  operationId?: string;
  tags: string[];
  surface: string;
};

export type SurfaceCoverage = {
  surface: string;
  privyCount: number;
  stewardCount: number;
  status: "covered" | "gap";
  privyExamples: string[];
  stewardExamples: string[];
};

export type OpenApiParityReport = {
  privyEndpointCount: number;
  stewardEndpointCount: number;
  coveredSurfaces: number;
  gapSurfaces: number;
  surfaces: SurfaceCoverage[];
};

const METHODS: HttpMethod[] = ["get", "post", "put", "patch", "delete"];

const SURFACE_RULES: Array<{ surface: string; patterns: RegExp[] }> = [
  { surface: "aggregations", patterns: [/aggregation/i] },
  { surface: "exchange-embed", patterns: [/kraken/i, /exchange/i] },
  { surface: "earn-yield", patterns: [/earn/i, /yield/i] },
  { surface: "fiat", patterns: [/fiat/i, /onramp/i, /offramp/i] },
  { surface: "auth", patterns: [/\/auth/i, /oauth/i, /login/i, /mfa/i, /passkey/i] },
  { surface: "users", patterns: [/user/i, /linked.?account/i, /identity/i] },
  { surface: "wallets", patterns: [/wallet/i, /embedded/i, /pregenerated/i] },
  { surface: "vault-signing", patterns: [/vault/i, /sign/i, /transaction/i, /message/i] },
  { surface: "accounts", patterns: [/account/i, /portfolio/i, /balance/i] },
  { surface: "policies", patterns: [/polic/i, /condition/i, /rule/i, /quorum/i, /signer/i] },
  {
    surface: "actions",
    patterns: [/action/i, /intent/i, /transfer/i, /swap/i, /earn/i, /bridge/i],
  },
  { surface: "webhooks", patterns: [/webhook/i, /event/i] },
  { surface: "apps", patterns: [/\/apps?\b/i, /app.?client/i, /tenant/i, /allowlist/i, /origin/i] },
  { surface: "audit", patterns: [/audit/i, /log/i] },
];

function endpointText(endpoint: Pick<Endpoint, "method" | "path" | "operationId" | "tags">) {
  return `${endpoint.method.toUpperCase()} ${endpoint.path} ${endpoint.operationId ?? ""} ${endpoint.tags.join(" ")}`;
}

export function classifyEndpoint(
  endpoint: Pick<Endpoint, "method" | "path" | "operationId" | "tags">,
) {
  const text = endpointText(endpoint);
  for (const rule of SURFACE_RULES) {
    if (rule.patterns.some((pattern) => pattern.test(text))) {
      return rule.surface;
    }
  }
  return "unknown";
}

export function listEndpoints(spec: OpenApiDocument): Endpoint[] {
  const endpoints: Endpoint[] = [];
  for (const [path, operations] of Object.entries(spec.paths ?? {})) {
    for (const method of METHODS) {
      const operation = operations[method];
      if (!operation) {
        continue;
      }
      const endpoint = {
        method,
        path,
        operationId: operation.operationId,
        tags: operation.tags ?? [],
        surface: "unknown",
      };
      endpoint.surface = classifyEndpoint(endpoint);
      endpoints.push(endpoint);
    }
  }
  return endpoints.sort((a, b) =>
    `${a.surface}:${a.path}:${a.method}`.localeCompare(`${b.surface}:${b.path}:${b.method}`),
  );
}

export function compareOpenApiSpecs(
  privySpec: OpenApiDocument,
  stewardSpec: OpenApiDocument,
): OpenApiParityReport {
  const privyEndpoints = listEndpoints(privySpec);
  const stewardEndpoints = listEndpoints(stewardSpec);
  const surfaces = Array.from(new Set(privyEndpoints.map((endpoint) => endpoint.surface))).sort();
  const coverage = surfaces.map((surface): SurfaceCoverage => {
    const privySurfaceEndpoints = privyEndpoints.filter((endpoint) => endpoint.surface === surface);
    const stewardSurfaceEndpoints = stewardEndpoints.filter(
      (endpoint) => endpoint.surface === surface,
    );
    return {
      surface,
      privyCount: privySurfaceEndpoints.length,
      stewardCount: stewardSurfaceEndpoints.length,
      status: surface !== "unknown" && stewardSurfaceEndpoints.length > 0 ? "covered" : "gap",
      privyExamples: privySurfaceEndpoints
        .slice(0, 8)
        .map((endpoint) => `${endpoint.method.toUpperCase()} ${endpoint.path}`),
      stewardExamples: stewardSurfaceEndpoints
        .slice(0, 8)
        .map((endpoint) => `${endpoint.method.toUpperCase()} ${endpoint.path}`),
    };
  });

  return {
    privyEndpointCount: privyEndpoints.length,
    stewardEndpointCount: stewardEndpoints.length,
    coveredSurfaces: coverage.filter((surface) => surface.status === "covered").length,
    gapSurfaces: coverage.filter((surface) => surface.status === "gap").length,
    surfaces: coverage,
  };
}

async function loadOpenApi(value: string): Promise<OpenApiDocument> {
  if (/^https?:\/\//.test(value)) {
    const response = await fetch(value);
    if (!response.ok) {
      throw new Error(`Failed to fetch ${value}: ${response.status}`);
    }
    return (await response.json()) as OpenApiDocument;
  }
  return JSON.parse(await readFile(resolve(value), "utf8")) as OpenApiDocument;
}

function getArg(name: string, fallback: string) {
  const prefix = `${name}=`;
  const value = process.argv.find((arg) => arg.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

function printTextReport(report: OpenApiParityReport) {
  console.log(
    `Privy endpoints: ${report.privyEndpointCount}; Steward endpoints: ${report.stewardEndpointCount}; covered surfaces: ${report.coveredSurfaces}; gap surfaces: ${report.gapSurfaces}`,
  );
  for (const surface of report.surfaces) {
    const marker = surface.status === "covered" ? "OK" : "GAP";
    console.log(
      `${marker} ${surface.surface}: Privy ${surface.privyCount}, Steward ${surface.stewardCount}`,
    );
    if (surface.status === "gap") {
      console.log(`  Privy examples: ${surface.privyExamples.join(", ")}`);
    }
  }
}

export async function runOpenApiParityCli() {
  const privy = getArg("--privy", DEFAULT_PRIVY_OPENAPI_URL);
  const steward = getArg("--steward", "docs/openapi.json");
  const report = compareOpenApiSpecs(await loadOpenApi(privy), await loadOpenApi(steward));
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printTextReport(report);
  }
  if (process.argv.includes("--fail-on-gap") && report.gapSurfaces > 0) {
    process.exitCode = 1;
  }
}

if (import.meta.main) {
  await runOpenApiParityCli();
}
