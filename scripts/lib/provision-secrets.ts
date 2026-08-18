import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface ProvisionSecrets {
  tenantApiKey?: string;
  agentId?: string;
  apiUrl?: string;
  tradeSessionId?: string;
  jwt?: string;
}

function envLine(name: string, value: string | undefined): string | null {
  if (value === undefined) return null;
  if (/[\0\r\n]/.test(value)) {
    throw new Error(`${name} contains an unsupported control character`);
  }
  return `${name}=${value}`;
}

/**
 * Persist provisioning credentials without placing them in stdout or process
 * argv. The first call creates a private directory/file; later calls may update
 * that same file as provisioning produces additional credentials.
 */
export function writeProvisionSecrets(
  secrets: ProvisionSecrets,
  existingPath?: string,
  temporaryDirectory: string = tmpdir(),
): string {
  const lines = [
    "# Steward provisioning credentials — keep private and delete after use.",
    envLine("STEWARD_TENANT_API_KEY", secrets.tenantApiKey),
    envLine("STEWARD_AGENT_ID", secrets.agentId),
    envLine("STEWARD_API_URL", secrets.apiUrl),
    envLine("STEWARD_TRADE_SESSION_ID", secrets.tradeSessionId),
    envLine("STEWARD_JWT", secrets.jwt),
  ].filter((line): line is string => line !== null);
  const path =
    existingPath ??
    join(mkdtempSync(join(temporaryDirectory, "steward-provision-")), "credentials.env");

  writeFileSync(path, `${lines.join("\n")}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: existingPath ? "w" : "wx",
  });
  // `mode` only applies on creation. Reassert it when updating an existing
  // output in case an operator accidentally changed its permissions.
  chmodSync(path, 0o600);
  return path;
}
