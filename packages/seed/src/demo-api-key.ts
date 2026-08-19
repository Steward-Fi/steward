import {
  closeSync,
  fchmodSync,
  constants as fsConstants,
  fstatSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  openSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { type ApiKeyPair, generateApiKey } from "@stwd/auth";

/**
 * Mint a fresh credential for each demo seed run.
 *
 * Demo data may be loaded into an internet-reachable environment, so a
 * repository-known key is unsafe even when the package is primarily intended
 * for local development.
 */
export function generateDemoApiKey(): ApiKeyPair {
  return generateApiKey();
}

/** Persist the one-time credential without exposing it to terminal/CI logs. */
export function writeDemoCredentials(
  tenantId: string,
  apiKey: string,
  outputPath = process.env.STEWARD_DEMO_CREDENTIALS_FILE ?? ".steward/demo-credentials.env",
): string {
  if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(tenantId)) {
    throw new Error("Demo credential tenant id is invalid");
  }
  const path = resolve(outputPath);
  const parentPath = dirname(path);
  mkdirSync(parentPath, { recursive: true, mode: 0o700 });
  const parent = lstatSync(parentPath);
  if (!parent.isDirectory() || parent.isSymbolicLink()) {
    throw new Error("Demo credentials parent must be a real directory");
  }
  if (typeof process.geteuid === "function" && parent.uid !== process.geteuid()) {
    throw new Error("Demo credentials parent must be owned by the current user");
  }
  const fd = openSync(
    path,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    0o600,
  );
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) {
      throw new Error("Demo credentials output must be a regular, non-linked file");
    }
    if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) {
      throw new Error("Demo credentials output must be owned by the current user");
    }
    fchmodSync(fd, 0o600);
    ftruncateSync(fd, 0);
    writeFileSync(fd, `STEWARD_TENANT_ID=${tenantId}\nSTEWARD_API_KEY=${apiKey}\n`, "utf8");
  } finally {
    closeSync(fd);
  }
  return path;
}
