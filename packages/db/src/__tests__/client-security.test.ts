import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { assertDatabaseUrlTls } from "../client";

const originalNodeEnv = process.env.NODE_ENV;
const originalOverride = process.env.STEWARD_ALLOW_INSECURE_DB;
const originalUnverifiedTlsOverride = process.env.STEWARD_ALLOW_UNVERIFIED_DB_TLS;

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;
  if (originalOverride === undefined) delete process.env.STEWARD_ALLOW_INSECURE_DB;
  else process.env.STEWARD_ALLOW_INSECURE_DB = originalOverride;
  if (originalUnverifiedTlsOverride === undefined)
    delete process.env.STEWARD_ALLOW_UNVERIFIED_DB_TLS;
  else process.env.STEWARD_ALLOW_UNVERIFIED_DB_TLS = originalUnverifiedTlsOverride;
});

describe("database transport security", () => {
  test("fails closed when a production connection string cannot be parsed", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_DB;
    expect(() => assertDatabaseUrlTls("host=db.internal dbname=steward")).toThrow("valid URL");
  });

  test("does not accept sslmode text outside the query parameter", () => {
    process.env.NODE_ENV = "production";
    expect(() =>
      assertDatabaseUrlTls("postgres://user:sslmode=require@db.example/steward"),
    ).toThrow("sslmode=verify-full");
    expect(() => assertDatabaseUrlTls("postgres://user:pass@db.example/sslmode=require")).toThrow(
      "sslmode=verify-full",
    );
  });

  test("rejects ambiguous duplicate sslmode parameters", () => {
    process.env.NODE_ENV = "production";
    expect(() =>
      assertDatabaseUrlTls(
        "postgres://user:pass@db.example/steward?sslmode=require&sslmode=disable",
      ),
    ).toThrow("sslmode=verify-full");
  });

  test("accepts a single enforced TLS mode and local development sockets", () => {
    process.env.NODE_ENV = "production";
    expect(() =>
      assertDatabaseUrlTls("postgres://user:pass@db.example/steward?sslmode=verify-full"),
    ).not.toThrow();
    expect(() => assertDatabaseUrlTls("postgres://localhost/steward")).not.toThrow();
  });

  test("rejects sslmode=require in production unless its distinct risk is acknowledged (SEC-087)", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_UNVERIFIED_DB_TLS;
    process.env.STEWARD_ALLOW_INSECURE_DB = "true";
    expect(() =>
      assertDatabaseUrlTls("postgres://user:pass@db.example/steward?sslmode=require"),
    ).toThrow("STEWARD_ALLOW_UNVERIFIED_DB_TLS=true");
  });

  test("accepts sslmode=require only with the explicit unverified-TLS acknowledgement", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_UNVERIFIED_DB_TLS = "true";
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(() =>
        assertDatabaseUrlTls("postgres://user:pass@db.example/steward?sslmode=require"),
      ).not.toThrow();
      expect(warn).toHaveBeenCalled();
      expect(String(warn.mock.calls[0]?.[0] ?? "")).toContain("verify-full");
    } finally {
      warn.mockRestore();
    }
  });

  test("does not warn for verify-ca / verify-full (SEC-087)", () => {
    process.env.NODE_ENV = "production";
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      assertDatabaseUrlTls("postgres://user:pass@db.example/steward?sslmode=verify-full");
      assertDatabaseUrlTls("postgres://user:pass@db.example/steward?sslmode=verify-ca");
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});
