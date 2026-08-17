import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { assertDatabaseUrlTls } from "../client";

const originalNodeEnv = process.env.NODE_ENV;
const originalOverride = process.env.STEWARD_ALLOW_INSECURE_DB;

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;
  if (originalOverride === undefined) delete process.env.STEWARD_ALLOW_INSECURE_DB;
  else process.env.STEWARD_ALLOW_INSECURE_DB = originalOverride;
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
    ).toThrow("sslmode=require");
    expect(() => assertDatabaseUrlTls("postgres://user:pass@db.example/sslmode=require")).toThrow(
      "sslmode=require",
    );
  });

  test("rejects ambiguous duplicate sslmode parameters", () => {
    process.env.NODE_ENV = "production";
    expect(() =>
      assertDatabaseUrlTls(
        "postgres://user:pass@db.example/steward?sslmode=require&sslmode=disable",
      ),
    ).toThrow("sslmode=require");
  });

  test("accepts a single enforced TLS mode and local development sockets", () => {
    process.env.NODE_ENV = "production";
    expect(() =>
      assertDatabaseUrlTls("postgres://user:pass@db.example/steward?sslmode=verify-full"),
    ).not.toThrow();
    expect(() => assertDatabaseUrlTls("postgres://localhost/steward")).not.toThrow();
  });

  test("accepts sslmode=require in production but warns it does not verify the peer (SEC-087)", () => {
    process.env.NODE_ENV = "production";
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
