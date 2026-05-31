import { isIP } from "node:net";

const ALLOW_INSECURE_WEBHOOK_URLS = process.env.STEWARD_ALLOW_INSECURE_WEBHOOK_URLS === "true";

function isPrivateIpv4(hostname: string): boolean {
  const octets = hostname.split(".").map((part) => Number(part));
  if (
    octets.length !== 4 ||
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return false;
  }
  const [a, b] = octets;
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a === 0
  );
}

function mappedIpv4FromIpv6(hostname: string): string | null {
  const normalized = hostname.toLowerCase();
  const dotted = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return dotted[1];

  const hex = normalized.match(/^(?:::ffff:|0:0:0:0:0:ffff:)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (!hex) return null;
  const high = Number.parseInt(hex[1], 16);
  const low = Number.parseInt(hex[2], 16);
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function expandIpv6Words(hostname: string): number[] | null {
  const normalized = hostname.toLowerCase();
  const halves = normalized.split("::");
  if (halves.length > 2) return null;

  const parseWords = (part: string): number[] | null => {
    if (!part) return [];
    const words = part.split(":");
    const parsed = words.map((word) => {
      if (!/^[0-9a-f]{1,4}$/.test(word)) return Number.NaN;
      return Number.parseInt(word, 16);
    });
    return parsed.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)
      ? null
      : parsed;
  };

  const left = parseWords(halves[0]);
  const right = parseWords(halves[1] ?? "");
  if (!left || !right) return null;

  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;

  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function embeddedIpv4FromIpv6(hostname: string): string | null {
  const words = expandIpv6Words(hostname);
  if (!words || words.length !== 8) return null;

  const fromWords = (high: number, low: number) =>
    [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");

  const isNat64WellKnown =
    words[0] === 0x64 &&
    words[1] === 0xff9b &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0;
  if (isNat64WellKnown) return fromWords(words[6], words[7]);

  const isNat64LocalUse =
    words[0] === 0x64 && words[1] === 0xff9b && words[2] === 1 && words[3] === 0;
  if (isNat64LocalUse) return fromWords(words[6], words[7]);

  if (words[0] === 0x2002) return fromWords(words[1], words[2]);

  return null;
}

function isPrivateIpv6(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  const ipv4Mapped = mappedIpv4FromIpv6(normalized);
  if (ipv4Mapped) return isPrivateIpv4(ipv4Mapped);
  const ipv4Embedded = embeddedIpv4FromIpv6(normalized);
  if (ipv4Embedded) return isPrivateIpv4(ipv4Embedded);
  const words = expandIpv6Words(normalized);
  if (words?.[0] === 0x2001 && (words[1] === 0 || words[1] === 0xdb8)) return true;
  if (words?.[0] !== undefined && (words[0] & 0xffc0) === 0xfec0) return true;
  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("ff")
  );
}

export function validateWebhookUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) return "url must not include credentials";

    if (parsed.protocol !== "https:") {
      if (!ALLOW_INSECURE_WEBHOOK_URLS || parsed.protocol !== "http:") {
        return "url must use https";
      }
    }

    const hostname = parsed.hostname
      .replace(/^\[|\]$/g, "")
      .replace(/\.+$/g, "")
      .toLowerCase();
    if (!hostname) return "url must include a host";
    if (hostname === "localhost" || hostname.endsWith(".localhost")) {
      return "url host must be public";
    }
    if (hostname.endsWith(".local") || hostname.endsWith(".internal")) {
      return "url host must be public";
    }

    const ipVersion = isIP(hostname);
    if (ipVersion === 4 && isPrivateIpv4(hostname)) return "url host must be public";
    if (ipVersion === 6 && isPrivateIpv6(hostname)) return "url host must be public";

    return null;
  } catch {
    return "url must be a valid HTTPS URL";
  }
}
