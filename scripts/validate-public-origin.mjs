#!/usr/bin/env node

import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

function ipv4Octets(address) {
  const parts = address.split(".").map(Number);
  return parts.length === 4 &&
    parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? parts
    : null;
}

function ipv6Value(address) {
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = halves.length === 2 ? [...left, ...Array(missing).fill("0"), ...right] : left;
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) {
    return null;
  }
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n);
}

function inIpv6Prefix(value, prefix, bits) {
  const shift = BigInt(128 - bits);
  return value >> shift === prefix >> shift;
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
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }
  if (version !== 6) return false;
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return isPublicIp(mapped[1]);
  const value = ipv6Value(normalized);
  if (value === null) return false;
  const prefix = (address) => ipv6Value(address);
  const globalUnicast = prefix("2000::");
  if (!inIpv6Prefix(value, globalUnicast, 3)) return false;
  // Conservative denylist for IANA special-purpose ranges inside 2000::/3:
  // protocol assignments/benchmarking, documentation, deprecated 6to4, and
  // the documentation block formerly carved from the global-unicast pool.
  return !(
    inIpv6Prefix(value, prefix("2001::"), 23) ||
    inIpv6Prefix(value, prefix("2001:db8::"), 32) ||
    inIpv6Prefix(value, prefix("2002::"), 16) ||
    inIpv6Prefix(value, prefix("3fff::"), 20)
  );
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

export async function resolvePublicHttpsOrigin(input, lookup = dnsLookup) {
  const origin = parsePublicHttpsOrigin(input);
  const hostname = new URL(origin).hostname.replace(/^\[|\]$/g, "");
  if (isIP(hostname)) return origin;
  const answers = await lookup(hostname, { all: true, verbatim: true });
  if (!Array.isArray(answers) || answers.length === 0) {
    throw new Error("health authority did not resolve");
  }
  if (answers.some((answer) => !isPublicIp(answer.address))) {
    throw new Error("health authority resolved to a non-public address");
  }
  return origin;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [modeOrOrigin, value] = process.argv.slice(2);
  try {
    if (modeOrOrigin === "--ip") {
      if (!value || !isPublicIp(value)) throw new Error("probe peer must be a public address");
      process.stdout.write(value);
    } else if (modeOrOrigin === "--resolve-origin") {
      if (!value) throw new Error("health authority is required");
      process.stdout.write(await resolvePublicHttpsOrigin(value));
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
}
