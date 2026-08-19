import { describe, expect, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import ts from "typescript";

const ROOT = join(import.meta.dir, "../..");
const RUNTIME_ROOTS = ["packages", "web/src"];

async function runtimeSources(directory: string): Promise<string[]> {
  const paths: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__tests__" || entry.name === "dist" || entry.name === "node_modules")
        continue;
      paths.push(...(await runtimeSources(path)));
    } else if (
      entry.isFile() &&
      /\.tsx?$/.test(entry.name) &&
      !/\.(?:test|spec)\.tsx?$/.test(entry.name) &&
      !entry.name.endsWith(".d.ts")
    ) {
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
      "detail",
      "logWarn",
      "dispatchWebhook",
      "trackAuditEvent",
      "writeAuditEvent",
      "auditWriter",
      "recordAudit",
      "recordRequiredAudit",
      "appendRequiredAudit",
      "recordReservationFailure",
    ].includes(name) ||
    name.endsWith("Audit") ||
    /^audit[A-Z]/.test(name)
  );
}

function unsafeTelemetryArguments(source: ts.SourceFile): string[] {
  const failures: string[] = [];
  const reported = new Set<string>();
  const report = (node: ts.Node): void => {
    const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
    const failure = `${source.fileName}:${line}: ${node.getText(source).slice(0, 160)}`;
    if (!reported.has(failure)) {
      reported.add(failure);
      failures.push(failure);
    }
  };
  const bindingNames = (name: ts.BindingName): string[] => {
    if (ts.isIdentifier(name)) return [name.text];
    return name.elements.flatMap((element) =>
      ts.isOmittedExpression(element) ? [] : bindingNames(element.name),
    );
  };
  const inspectTaintedScope = (scope: ts.Node, caughtNames: string[]): void => {
    const tainted = new Set(caughtNames);
    const taintMutationTarget = (candidate: ts.Expression): void => {
      let target: ts.Expression = candidate;
      while (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
        target = target.expression;
      }
      if (ts.isIdentifier(target)) tainted.add(target.text);
    };
    const isTainted = (candidate: ts.Node): boolean => {
      if (
        ts.isPropertyAccessExpression(candidate) &&
        ["field", "transactionHash"].includes(candidate.name.text)
      ) {
        // These typed domain-error fields are intentionally bounded identifiers,
        // not provider-controlled exception text.
        return false;
      }
      if (ts.isCallExpression(candidate)) {
        const name = sinkName(candidate.expression);
        if (
          [
            "extractRpcErrorMessage",
            "isDefiniteVenueRejection",
            "isRpcError",
            "redactSensitiveText",
            "redactedThrownDiagnostics",
            "sanitizeErrorMessage",
          ].includes(name) ||
          (ts.isPropertyAccessExpression(candidate.expression) &&
            ["endsWith", "includes", "startsWith"].includes(candidate.expression.name.text))
        ) {
          return false;
        }
      }
      if (ts.isConditionalExpression(candidate)) {
        return isTainted(candidate.whenTrue) || isTainted(candidate.whenFalse);
      }
      if (ts.isIdentifier(candidate) && tainted.has(candidate.text)) {
        const parent = candidate.parent;
        if (
          (ts.isPropertyAssignment(parent) && parent.name === candidate) ||
          (ts.isPropertyAccessExpression(parent) && parent.name === candidate) ||
          (ts.isMethodDeclaration(parent) && parent.name === candidate)
        ) {
          return false;
        }
        return true;
      }
      return candidate.getChildren(source).some(isTainted);
    };
    const visitTaintedNode = (node: ts.Node): void => {
      if (node !== scope && ts.isCatchClause(node)) return;
      if (ts.isVariableDeclaration(node)) {
        const names = bindingNames(node.name);
        if (node.initializer && isTainted(node.initializer)) {
          for (const name of names) tainted.add(name);
        }
      }
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        isTainted(node.right)
      ) {
        if (ts.isIdentifier(node.left)) {
          tainted.add(node.left.text);
        } else if (
          ts.isPropertyAccessExpression(node.left) ||
          ts.isElementAccessExpression(node.left)
        ) {
          taintMutationTarget(node.left);
        }
      }
      if (ts.isCallExpression(node)) {
        if (
          ts.isPropertyAccessExpression(node.expression) &&
          ["push", "unshift", "splice", "set"].includes(node.expression.name.text) &&
          node.arguments.some(isTainted)
        ) {
          taintMutationTarget(node.expression.expression);
        }
        if (
          ts.isPropertyAccessExpression(node.expression) &&
          ts.isIdentifier(node.expression.expression) &&
          node.expression.expression.text === "Object" &&
          node.expression.name.text === "assign" &&
          node.arguments.length > 1 &&
          node.arguments.slice(1).some(isTainted)
        ) {
          taintMutationTarget(node.arguments[0]);
        }
        const isConsoleSink =
          ts.isPropertyAccessExpression(node.expression) &&
          ts.isIdentifier(node.expression.expression) &&
          node.expression.expression.text === "console" &&
          ["error", "warn", "log"].includes(node.expression.name.text);
        const name = sinkName(node.expression);
        if (isConsoleSink || isTelemetrySinkName(name)) {
          for (const argument of node.arguments) {
            if (isTainted(argument)) report(argument);
          }
        }
      }
      ts.forEachChild(node, visitTaintedNode);
    };
    visitTaintedNode(scope);
  };
  const inspectRejectionCallback = (candidate: ts.Expression | undefined): void => {
    if (!candidate) return;
    if (!ts.isArrowFunction(candidate) && !ts.isFunctionExpression(candidate)) {
      const isDirectConsoleSink =
        ts.isPropertyAccessExpression(candidate) &&
        ts.isIdentifier(candidate.expression) &&
        candidate.expression.text === "console" &&
        ["error", "warn", "log"].includes(candidate.name.text);
      if (
        isDirectConsoleSink ||
        ((ts.isIdentifier(candidate) || ts.isPropertyAccessExpression(candidate)) &&
          isTelemetrySinkName(sinkName(candidate)))
      ) {
        report(candidate);
      }
      return;
    }
    const caughtNames = candidate.parameters.flatMap((parameter) => bindingNames(parameter.name));
    if (caughtNames.length > 0) inspectTaintedScope(candidate.body, caughtNames);
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCatchClause(node)) {
      const variable = node.variableDeclaration?.name;
      if (variable) inspectTaintedScope(node.block, bindingNames(variable));
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      if (node.expression.name.text === "catch") {
        inspectRejectionCallback(node.arguments[0]);
      } else if (node.expression.name.text === "then") {
        inspectRejectionCallback(node.arguments[1]);
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

  test("tracks aliases passed to telemetry sinks", () => {
    expect(
      failuresForSnippet(`
        try {
          doThing();
        } catch (err) {
          const detail = err.message;
          const payload = { detail };
          console.error(payload);
        }
      `),
    ).toHaveLength(1);
  });

  test("tracks caught values written into mutable telemetry payloads", () => {
    expect(
      failuresForSnippet(`
        try {
          doThing();
        } catch (err) {
          const payload = { detail: "safe" };
          payload.detail = err.message;
          console.error(payload);

          const values = [];
          values.push(err.stack);
          writeAuditEvent({ values });
        }
      `),
    ).toHaveLength(2);
  });

  test("allows aliases of bounded diagnostics", () => {
    expect(
      failuresForSnippet(`
        try {
          doThing();
        } catch (err) {
          const diagnostics = redactedThrownDiagnostics(err);
          console.error("failed", diagnostics);
        }
      `),
    ).toEqual([]);
  });

  test("flags raw Promise rejection callback values at telemetry sinks", () => {
    expect(
      failuresForSnippet(`
        doThing().catch((error) => {
          const payload = { message: error.message };
          console.error(payload);
        });

        doOtherThing().then(undefined, (reason) => {
          writeAuditEvent({ reason: String(reason) });
        });
      `),
    ).toHaveLength(2);
  });

  test("flags telemetry sinks passed directly as Promise rejection callbacks", () => {
    expect(
      failuresForSnippet(`
        doThing().catch(console.error);
        doOtherThing().then(undefined, writeAuditEvent);
      `),
    ).toHaveLength(2);
  });

  test("allows bounded diagnostics in Promise rejection callbacks", () => {
    expect(
      failuresForSnippet(`
        doThing().catch((error) => {
          console.error("failed", redactedThrownDiagnostics(error));
        });

        doOtherThing().then(undefined, (reason) => {
          writeAuditEvent({ diagnostics: redactedThrownDiagnostics(reason) });
        });
      `),
    ).toEqual([]);
  });

  test("never passes raw throwables, messages, or stacks to runtime telemetry", async () => {
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
