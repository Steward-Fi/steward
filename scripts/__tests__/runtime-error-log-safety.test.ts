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

function unsafeConsoleArguments(source: ts.SourceFile): string[] {
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
      const sinkName = ts.isIdentifier(node.expression) ? node.expression.text : "";
      const isTelemetrySink =
        sinkName === "logWarn" || /(?:audit|Audit|dispatchWebhook)$/.test(sinkName);
      if (!isConsoleSink && !isTelemetrySink) {
        ts.forEachChild(node, visit);
        return;
      }
      for (const argument of node.arguments) {
        const text = argument.getText(source);
        if (text.includes("redactedThrownDiagnostics(")) continue;
        const referencesCaughtThrowable = (candidate: ts.Node): boolean => {
          if (ts.isIdentifier(candidate) && caughtThrowables.has(candidate.text)) return true;
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

describe("runtime error logging", () => {
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
        failures.push(...unsafeConsoleArguments(source));
      }
    }
    expect(failures).toEqual([]);
  });
});
