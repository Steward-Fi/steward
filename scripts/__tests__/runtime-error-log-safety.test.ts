import { describe, expect, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import ts from "typescript";

const ROOT = join(import.meta.dir, "../..");
const RUNTIME_ROOTS = [
  "packages/api/src",
  "packages/proxy/src",
  "packages/auth/src",
  "packages/plugin-trading/src",
  "packages/redis/src",
  "packages/agent-trader/src",
];

async function runtimeSources(directory: string): Promise<string[]> {
  const paths: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__tests__" || entry.name === "dist") continue;
      paths.push(...(await runtimeSources(path)));
    } else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
      paths.push(path);
    }
  }
  return paths;
}

function sinkName(expression: ts.LeftHandSideExpression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return "";
}

function isTelemetrySinkName(name: string): boolean {
  return (
    [
      "logWarn",
      "dispatchWebhook",
      "trackAuditEvent",
      "writeAuditEvent",
      "auditWriter",
      "recordAudit",
      "recordRequiredAudit",
      "appendRequiredAudit",
    ].includes(name) ||
    name.endsWith("Audit") ||
    /^audit[A-Z]/.test(name)
  );
}

function unsafeTelemetryArguments(source: ts.SourceFile): string[] {
  const failures: string[] = [];
  const caughtThrowables = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (ts.isCatchClause(node)) {
      const variable = node.variableDeclaration?.name;
      if (variable && ts.isIdentifier(variable)) {
        caughtThrowables.add(variable.text);
        ts.forEachChild(node.block, visit);
        caughtThrowables.delete(variable.text);
        return;
      }
    }
    if (ts.isCallExpression(node)) {
      const isConsoleSink =
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        node.expression.expression.text === "console" &&
        ["error", "warn", "log"].includes(node.expression.name.text);
      const name = sinkName(node.expression);
      const isTelemetrySink = isTelemetrySinkName(name);
      if (!isConsoleSink && !isTelemetrySink) {
        ts.forEachChild(node, visit);
        return;
      }
      for (const argument of node.arguments) {
        const text = argument.getText(source);
        const referencesCaughtThrowable = (candidate: ts.Node): boolean => {
          if (
            ts.isCallExpression(candidate) &&
            ts.isIdentifier(candidate.expression) &&
            candidate.expression.text === "redactedThrownDiagnostics"
          ) {
            return false;
          }
          if (ts.isIdentifier(candidate) && caughtThrowables.has(candidate.text)) {
            const parent = candidate.parent;
            // Property names such as `{ error: "fixed" }` and `value.error`
            // are labels, not references to a catch binding with the same name.
            if (
              (ts.isPropertyAssignment(parent) && parent.name === candidate) ||
              (ts.isPropertyAccessExpression(parent) && parent.name === candidate) ||
              (ts.isMethodDeclaration(parent) && parent.name === candidate)
            ) {
              return false;
            }
            return true;
          }
          return candidate.getChildren(source).some(referencesCaughtThrowable);
        };
        if (
          referencesCaughtThrowable(argument) ||
          /^(?:err|error|e|reason|releaseError)$/i.test(text) ||
          /(?:err|error|reason|releaseError)\s*\.\s*(?:message|stack)\b/i.test(text) ||
          /String\(\s*(?:err|error|e|reason|releaseError)\s*\)/i.test(text) ||
          /\$\{\s*(?:err|error|e|reason|releaseError)\s*\}/i.test(text)
        ) {
          const line = source.getLineAndCharacterOfPosition(argument.getStart(source)).line + 1;
          failures.push(`${source.fileName}:${line}: ${text.slice(0, 160)}`);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return failures;
}

function failuresForSnippet(text: string): string[] {
  const source = ts.createSourceFile(
    "snippet.ts",
    text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  return unsafeTelemetryArguments(source);
}

describe("runtime error logging", () => {
  test("flags raw caught throwables across audit and webhook sink variants", () => {
    expect(
      failuresForSnippet(
        `
        async function f(ctx: { writeAuditEvent: (value: unknown) => Promise<void>; auditWriter: (value: unknown) => Promise<void> }) {
          try {
            doThing();
          } catch (err) {
            await writeAuditEvent({ metadata: { error: err.message } });
            trackAuditEvent({ metadata: { error: String(err) } });
            await ctx.writeAuditEvent({ metadata: { error: err.message } });
            await ctx.auditWriter({ metadata: { error: err.message } });
            await recordAudit({ reason: err.message });
            await recordRequiredAudit({ reason: err.message });
            await appendRequiredAudit({ reason: err.message });
            await auditRecoveryEvent("tenant", { error: err.message });
            dispatchWebhook("tenant", "agent", "tx_failed", { error: err.message });
            logWarn("warn", { error: err.message });
            console.error("oops", err.message);
          }
        }
        `,
      ).length,
    ).toBeGreaterThan(0);
  });

  test("allows bounded classifiers at telemetry sinks", () => {
    expect(
      failuresForSnippet(
        `
        async function f(ctx: { writeAuditEvent: (value: unknown) => Promise<void> }) {
          try {
            doThing();
          } catch (err) {
            await writeAuditEvent({ metadata: { ...redactedThrownDiagnostics(err) } });
            trackAuditEvent({ metadata: { ...redactedThrownDiagnostics(err) } });
            await ctx.writeAuditEvent({ metadata: { ...redactedThrownDiagnostics(err) } });
            dispatchWebhook("tenant", "agent", "tx_failed", {
              error: "Transaction failed",
              ...redactedThrownDiagnostics(err),
            });
            logWarn("warn", { ...redactedThrownDiagnostics(err) });
            console.error("oops", redactedThrownDiagnostics(err));
          }
        }
        `,
      ),
    ).toEqual([]);
  });

  test("does not let one sanitizer call mask a sibling raw throwable", () => {
    expect(
      failuresForSnippet(`
        try {
          doThing();
        } catch (err) {
          console.error({ safe: redactedThrownDiagnostics(err), raw: err });
          writeAuditEvent({
            metadata: { diagnostics: redactedThrownDiagnostics(err), message: err.message },
          });
        }
      `),
    ).toHaveLength(2);
  });

  test("never passes raw throwables, messages, or stacks to console sinks", async () => {
    const failures: string[] = [];
    for (const root of RUNTIME_ROOTS) {
      for (const path of await runtimeSources(join(ROOT, root))) {
        const text = await readFile(path, "utf8");
        const source = ts.createSourceFile(
          relative(ROOT, path),
          text,
          ts.ScriptTarget.Latest,
          true,
          ts.ScriptKind.TS,
        );
        failures.push(...unsafeTelemetryArguments(source));
      }
    }
    expect(failures).toEqual([]);
  });
});
