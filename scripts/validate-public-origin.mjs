#!/usr/bin/env node

import { isIP } from "node:net";

function ipv4Octets(address) {
  const parts = address.split(".").map(Number);
  return parts.length === 4 &&
    parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? parts
    : null;
}

export function isPublicIp(address) {
  const normalized = address
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .split("%")[0];
  const version = isIP(normalized);
  if (version === 4) {
    const octets = ipv4Octets(normalized);
    if (!octets) return false;
    const [a, b, c] = octets;
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && ((b === 0 && (c === 0 || c === 2)) || b === 168)) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }
  if (version !== 6) return false;
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return isPublicIp(mapped[1]);
  // Globally routable IPv6 unicast is 2000::/3. This rejects ULA, link-local,
  // site-local, multicast, documentation, unspecified, and loopback space.
  return /^[23][0-9a-f]{3}:/i.test(normalized) && !/^2001:(?:0?db8):/i.test(normalized);
}

export function parsePublicHttpsOrigin(input) {
  let parsed;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error("health authority must be a valid URL");
  }
  if (parsed.protocol !== "https:") throw new Error("health authority must use HTTPS");
  if (parsed.username || parsed.password)
    throw new Error("health authority must not contain userinfo");
  if (parsed.search || parsed.hash)
    throw new Error("health authority must not contain query or fragment");
  if (parsed.pathname !== "/") throw new Error("health authority must be a root origin");
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local")) {
    throw new Error("health authority must be public");
  }
  if (isIP(hostname) && !isPublicIp(hostname)) {
    throw new Error("health authority must be public");
  }
  return parsed.origin;
}

const [modeOrOrigin, value] = process.argv.slice(2);
try {
  if (modeOrOrigin === "--ip") {
    if (!value || !isPublicIp(value)) throw new Error("probe peer must be a public address");
    process.stdout.write(value);
  } else {
    if (!modeOrOrigin) throw new Error("health authority is required");
    process.stdout.write(parsePublicHttpsOrigin(modeOrOrigin));
  }
} catch (error) {
  process.stderr.write(
    `[railway] ${error instanceof Error ? error.message : "invalid health authority"}\n`,
  );
  process.exitCode = 1;
}
