import { createHash } from "node:crypto";
import {
  CanonError,
  canonicalizeRawInternalGoogleAction,
  type GoogleCanonicalActionV1,
  type JsonValue,
} from "@stwd/shared";

export const GOOGLE_OPERATION_KEYS = [
  "google.gmail.messages.send",
  "google.calendar.events.list",
  "google.calendar.events.insert",
] as const;
export type GoogleOperationKey = (typeof GOOGLE_OPERATION_KEYS)[number];
export const isGoogleOperationKey = (v: unknown): v is GoogleOperationKey =>
  typeof v === "string" && (GOOGLE_OPERATION_KEYS as readonly string[]).includes(v);
export interface GoogleActionBuild {
  operationKey: GoogleOperationKey;
  method: "GET" | "POST";
  risk: "read" | "write";
  action: GoogleCanonicalActionV1;
  safeSummary: Record<string, unknown>;
  policyArgs: Record<string, unknown>;
}

const object = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== "object" || Array.isArray(v))
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "arguments must be an object");
  return v as Record<string, unknown>;
};
const exact = (o: Record<string, unknown>, keys: string[]) => {
  for (const k of Object.keys(o))
    if (!keys.includes(k)) throw new CanonError("CANON_UNKNOWN_FIELD", `unknown argument '${k}'`);
};
const str = (v: unknown, name: string, max: number, required = true): string | undefined => {
  if (v === undefined && !required) return undefined;
  if (typeof v !== "string" || v.length < 1 || v.length > max || /[\r\n]/.test(v))
    throw new CanonError("CANON_FIELD_TYPE_INVALID", `${name} is invalid`);
  return v;
};
const text = (v: unknown, name: string, maxBytes: number): string => {
  if (typeof v !== "string" || v.length < 1 || new TextEncoder().encode(v).byteLength > maxBytes)
    throw new CanonError("CANON_FIELD_TYPE_INVALID", `${name} is invalid`);
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = v.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff))
        throw new CanonError("CANON_UNICODE_INVALID", `${name} contains invalid unicode`);
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonError("CANON_UNICODE_INVALID", `${name} contains invalid unicode`);
    }
  }
  return v;
};
const email = (v: unknown): string => {
  const s = str(v, "recipient", 320)!;
  const parts = s.split("@");
  const labels = parts.length === 2 ? parts[1].split(".") : [];
  if (
    parts.length !== 2 ||
    !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(parts[0]) ||
    labels.length < 1 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
  )
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "recipient is invalid");
  return s.toLowerCase();
};
const sha = (s: string) => `sha256:${createHash("sha256").update(s).digest("hex")}`;

/** Strict RFC 3339 instant validation (mandatory timezone, real calendar date). */
const rfc3339Instant = (value: string): number | null => {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(
      value,
    );
  if (!match) return null;
  const [, year, month, day, hour, minute, second, , zone] = match;
  const instant = Date.parse(value);
  if (!Number.isFinite(instant)) return null;
  if (Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return null;
  const offsetMinutes =
    zone === "Z"
      ? 0
      : (zone.startsWith("-") ? -1 : 1) *
        (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6)));
  if (Math.abs(offsetMinutes) > 14 * 60) return null;
  const local = new Date(instant + offsetMinutes * 60_000);
  return local.getUTCFullYear() === Number(year) &&
    local.getUTCMonth() + 1 === Number(month) &&
    local.getUTCDate() === Number(day) &&
    local.getUTCHours() === Number(hour) &&
    local.getUTCMinutes() === Number(minute) &&
    local.getUTCSeconds() === Number(second)
    ? instant
    : null;
};

function gmail(raw: unknown): GoogleActionBuild {
  const a = object(raw);
  exact(a, ["to", "subject", "body"]);
  if (!Array.isArray(a.to) || a.to.length < 1 || a.to.length > 50)
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "to must contain 1..50 recipients");
  const to = [...new Set(a.to.map(email))].sort();
  const subject = str(a.subject, "subject", 998)!;
  const body = text(a.body, "body", 100_000);
  const rfc822 = [
    `To: ${to.join(", ")}`,
    `Subject: ${subject}`,
    "Content-Type: text/plain; charset=utf-8",
    "MIME-Version: 1.0",
    "",
    body,
  ].join("\r\n");
  const encoded = Buffer.from(rfc822, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const action = canonicalizeRawInternalGoogleAction({
    method: "POST",
    origin: "https://gmail.googleapis.com",
    path: "/gmail/v1/users/me/messages/send",
    contentType: "application/json",
    body: { raw: encoded },
  });
  const toDomainSet = [...new Set(to.map((x) => x.slice(x.lastIndexOf("@") + 1)))].sort();
  return {
    operationKey: "google.gmail.messages.send",
    method: "POST",
    risk: "write",
    action,
    safeSummary: {
      operation: "google.gmail.messages.send",
      recipientCount: to.length,
      toDomainSet,
      hasAttachment: false,
      subjectLength: [...subject].length,
      bodySha256: sha(body),
    },
    policyArgs: { toDomainSet, hasAttachment: false, subjectLength: [...subject].length },
  };
}

function list(raw: unknown): GoogleActionBuild {
  const a = raw === undefined ? {} : object(raw);
  exact(a, ["timeMin", "timeMax", "maxResults", "pageToken"]);
  const q: Array<[string, string]> = [];
  for (const k of ["timeMin", "timeMax"] as const)
    if (a[k] !== undefined) {
      const s = str(a[k], k, 64)!;
      if (rfc3339Instant(s) === null)
        throw new CanonError("CANON_FIELD_TYPE_INVALID", `${k} must be RFC3339`);
      q.push([k, s]);
    }
  const max = a.maxResults === undefined ? 50 : a.maxResults;
  if (!Number.isInteger(max) || (max as number) < 1 || (max as number) > 2500)
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "maxResults must be 1..2500");
  q.push(["maxResults", String(max)]);
  if (a.pageToken !== undefined) q.push(["pageToken", str(a.pageToken, "pageToken", 2048)!]);
  const action = canonicalizeRawInternalGoogleAction({
    method: "GET",
    origin: "https://www.googleapis.com",
    path: "/calendar/v3/calendars/primary/events",
    query: q,
  });
  return {
    operationKey: "google.calendar.events.list",
    method: "GET",
    risk: "read",
    action,
    safeSummary: { operation: "google.calendar.events.list", maxResults: max },
    policyArgs: { maxResults: max },
  };
}

function insert(raw: unknown): GoogleActionBuild {
  const a = object(raw);
  exact(a, ["summary", "start", "end", "attendees"]);
  const summary = str(a.summary, "summary", 1024)!;
  const start = str(a.start, "start", 64)!;
  const end = str(a.end, "end", 64)!;
  const startInstant = rfc3339Instant(start);
  const endInstant = rfc3339Instant(end);
  if (startInstant === null || endInstant === null || endInstant <= startInstant)
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "event time range is invalid");
  const attendees = a.attendees === undefined ? [] : a.attendees;
  if (!Array.isArray(attendees) || attendees.length > 100)
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "attendees is invalid");
  const emails = [...new Set(attendees.map(email))].sort();
  const body: Record<string, JsonValue> = {
    summary,
    start: { dateTime: start },
    end: { dateTime: end },
  };
  if (emails.length) body.attendees = emails.map((x) => ({ email: x }));
  const action = canonicalizeRawInternalGoogleAction({
    method: "POST",
    origin: "https://www.googleapis.com",
    path: "/calendar/v3/calendars/primary/events",
    contentType: "application/json",
    body,
  });
  return {
    operationKey: "google.calendar.events.insert",
    method: "POST",
    risk: "write",
    action,
    safeSummary: {
      operation: "google.calendar.events.insert",
      attendeeCount: emails.length,
      summaryLength: [...summary].length,
      start,
      end,
    },
    policyArgs: { attendeeCount: emails.length, start, end },
  };
}

export function buildGoogleAction(key: GoogleOperationKey, args: unknown): GoogleActionBuild {
  if (key === "google.gmail.messages.send") return gmail(args);
  if (key === "google.calendar.events.list") return list(args);
  return insert(args);
}
