import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertCompleteCoverage,
  assertWalletE2EInventory,
  checkCiTestInventory,
  extractJob,
  extractUnitMatrix,
  jobExecutesPackageTests,
  repositoryTestTargets,
} from "../check-ci-test-inventory";

describe("CI test inventory", () => {
  test("the repository workflows cover every test-bearing workspace package", () => {
    expect(() => checkCiTestInventory()).not.toThrow();
  });

  test("direct Bun test-file commands use explicit relative paths", () => {
    for (const workflow of [".github/workflows/ci.yml", ".github/workflows/pr.yml"]) {
      const source = readFileSync(workflow, "utf8");
      expect(
        source.match(/\bbun test packages\/[^\s]+\.(?:test|spec)\.[cm]?[jt]sx?/g) ?? [],
      ).toEqual([]);
    }
  });

  test("wallet E2E inventory requires its contract, both specs, and explicit workflow execution", () => {
    const root = mkdtempSync(join(tmpdir(), "steward-wallet-ci-inventory-"));
    try {
      for (const directory of [".github/workflows", "web/e2e/wallets"]) {
        mkdirSync(join(root, directory), { recursive: true });
      }
      for (const workflow of ["pr.yml", "ci.yml"]) {
        writeFileSync(
          join(root, ".github/workflows", workflow),
          [
            "run: bun test --isolate src e2e/wallets/wallet-e2e-contract.test.ts",
            "working-directory: web",
            "        run: bun run playwright install --with-deps chromium",
            "working-directory: web",
            "        run: bun -e 'import { chromium } from \"@playwright/test\"; const browser = await chromium.launch(); await browser.close();'",
          ].join("\n"),
        );
      }
      writeFileSync(
        join(root, ".github/workflows/wallet-e2e.yml"),
        [
          "run: bun test e2e/wallets/wallet-e2e-contract.test.ts",
          "run: bun run test:e2e:wallets:list",
          "run: bun run test:e2e:wallets",
        ].join("\n"),
      );
      for (const path of [
        "wallet-e2e-contract.test.ts",
        "metamask-siwe.spec.ts",
        "phantom-siws.spec.ts",
      ]) {
        writeFileSync(join(root, "web/e2e/wallets", path), "");
      }
      expect(() => assertWalletE2EInventory(root)).not.toThrow();
      writeFileSync(
        join(root, ".github/workflows", "pr.yml"),
        "run: bun test src e2e/wallets/wallet-e2e-contract.test.ts\n",
      );
      expect(() => assertWalletE2EInventory(root)).toThrow(
        ".github/workflows/pr.yml does not explicitly execute the isolated wallet E2E contract",
      );
      writeFileSync(
        join(root, ".github/workflows", "pr.yml"),
        [
          "run: bun test --isolate src e2e/wallets/wallet-e2e-contract.test.ts",
          "working-directory: web",
          "        run: bun run playwright install --with-deps chromium",
          "working-directory: web",
          "        run: bun -e 'import { chromium } from \"@playwright/test\"; const browser = await chromium.launch(); await browser.close();'",
        ].join("\n"),
      );
      const ciWorkflowPath = join(root, ".github/workflows", "ci.yml");
      const validCiWorkflow = readFileSync(ciWorkflowPath, "utf8");
      writeFileSync(
        ciWorkflowPath,
        validCiWorkflow.replace(
          "bun run playwright install --with-deps chromium",
          "bunx playwright install --with-deps chromium",
        ),
      );
      expect(() => assertWalletE2EInventory(root)).toThrow(
        ".github/workflows/ci.yml uses an unpinned Playwright CLI",
      );
      writeFileSync(
        ciWorkflowPath,
        validCiWorkflow.replace("const browser = await chromium.launch()", "const browser = null"),
      );
      expect(() => assertWalletE2EInventory(root)).toThrow(
        ".github/workflows/ci.yml does not verify the workspace Chromium launch",
      );
      writeFileSync(ciWorkflowPath, validCiWorkflow);
      rmSync(join(root, "web/e2e/wallets/phantom-siws.spec.ts"));
      expect(() => assertWalletE2EInventory(root)).toThrow(
        "wallet E2E inventory is missing web/e2e/wallets/phantom-siws.spec.ts",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("trade-session CI preserves the package's PGLite timeout", () => {
    for (const workflow of [".github/workflows/ci.yml", ".github/workflows/pr.yml"]) {
      const source = readFileSync(workflow, "utf8");
      expect(source).toContain("bun test --isolate --timeout 30000 packages/trade-sessions");
    }
  });

  test("a future unlisted test package fails closed", () => {
    expect(() =>
      assertCompleteCoverage(["packages/a", "packages/new"], ["packages/a"], []),
    ).toThrow("test-bearing targets missing from CI: packages/new");
  });

  test("discovers a non-JavaScript SDK without a package manifest", () => {
    const root = mkdtempSync(join(tmpdir(), "steward-ci-inventory-"));
    try {
      writeFileSync(join(root, "package.json"), JSON.stringify({ workspaces: [] }));
      mkdirSync(join(root, "packages", "native-sdk", "tests"), { recursive: true });
      writeFileSync(join(root, "packages", "native-sdk", "tests", "security.rs"), "#[test]\n");
      expect(repositoryTestTargets(root)).toEqual(["packages/native-sdk"]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("duplicate and stale declarations are rejected", () => {
    expect(() => assertCompleteCoverage(["packages/a"], ["packages/a", "packages/a"], [])).toThrow(
      "duplicate CI test inventory entries: packages/a",
    );
    expect(() => assertCompleteCoverage(["packages/a"], ["packages/a"], ["packages/a"])).toThrow(
      "duplicate CI test inventory entries: packages/a",
    );
    expect(() =>
      assertCompleteCoverage(["packages/a"], ["packages/a"], ["packages/removed"]),
    ).toThrow("CI inventory contains non-test targets: packages/removed");
  });

  test("workflow extraction is scoped to the unit and dedicated job blocks", () => {
    const workflow = [
      "jobs:",
      "  unit:",
      "    strategy:",
      "      matrix:",
      "        package:",
      "          - packages/a",
      "          - scripts/__tests__",
      "    steps: []",
      "  dedicated:",
      "    steps:",
      "      - run: bun test packages/b",
      "  later:",
      "    steps: []",
    ].join("\n");
    expect(extractUnitMatrix(workflow)).toEqual(["packages/a", "scripts/__tests__"]);
    expect(extractJob(workflow, "dedicated")).toContain("bun test packages/b");
    expect(extractJob(workflow, "dedicated")).not.toContain("later");
  });

  test("dedicated coverage requires an actual package test command", () => {
    const valid = [
      "  dedicated:",
      "    steps:",
      "      - name: Test package",
      "        working-directory: packages/a",
      "        run: bun run test",
    ].join("\n");
    const commentOnly = [
      "  dedicated:",
      "    # bun test packages/a",
      "    steps:",
      "      - name: packages/a bun test",
      "        run: bun run build",
    ].join("\n");
    const unrelated = [
      "  dedicated:",
      "    steps:",
      "      - name: Test another package",
      "        working-directory: packages/b",
      "        run: |",
      "          bun test packages/b",
      "          echo packages/a",
    ].join("\n");
    const echoed = ["  dedicated:", "    steps:", "      - run: echo bun test packages/a"].join(
      "\n",
    );
    const envPrefixed = [
      "  dedicated:",
      "    steps:",
      "      - name: Isolated package runner",
      "        run: TEST_JOBS=1 bun packages/a/scripts/run-tests-isolated.ts",
    ].join("\n");
    const unauditableBlock = [
      "  dedicated:",
      "    steps:",
      "      - name: Test package",
      "        working-directory: packages/a",
      "        run: |",
      "          bun run build",
      "          bun run test",
    ].join("\n");
    const heredocDecoy = [
      "  dedicated:",
      "    steps:",
      "      - name: Print instructions",
      "        run: |",
      "          cat <<'EOF'",
      "          bun test packages/a",
      "          EOF",
    ].join("\n");
    const maskedFailure = [
      "  dedicated:",
      "    steps:",
      "      - run: bun test packages/a || true",
    ].join("\n");
    const backgrounded = ["  dedicated:", "    steps:", "      - run: bun test packages/a &"].join(
      "\n",
    );
    const piped = [
      "  dedicated:",
      "    steps:",
      "      - run: bun test packages/a | tee test.log",
    ].join("\n");
    const skippedMaven = [
      "  dedicated:",
      "    steps:",
      "      - run: mvn -f packages/a/pom.xml test -DskipTests",
    ].join("\n");

    expect(jobExecutesPackageTests(extractJob(valid, "dedicated"), "packages/a")).toBe(true);
    expect(jobExecutesPackageTests(extractJob(commentOnly, "dedicated"), "packages/a")).toBe(false);
    expect(jobExecutesPackageTests(extractJob(unrelated, "dedicated"), "packages/a")).toBe(false);
    expect(jobExecutesPackageTests(extractJob(echoed, "dedicated"), "packages/a")).toBe(false);
    expect(jobExecutesPackageTests(extractJob(envPrefixed, "dedicated"), "packages/a")).toBe(true);
    expect(jobExecutesPackageTests(extractJob(unauditableBlock, "dedicated"), "packages/a")).toBe(
      false,
    );
    expect(jobExecutesPackageTests(extractJob(heredocDecoy, "dedicated"), "packages/a")).toBe(
      false,
    );
    expect(jobExecutesPackageTests(extractJob(maskedFailure, "dedicated"), "packages/a")).toBe(
      false,
    );
    expect(jobExecutesPackageTests(extractJob(backgrounded, "dedicated"), "packages/a")).toBe(
      false,
    );
    expect(jobExecutesPackageTests(extractJob(piped, "dedicated"), "packages/a")).toBe(false);
    expect(jobExecutesPackageTests(extractJob(skippedMaven, "dedicated"), "packages/a")).toBe(
      false,
    );
  });

  test("recognizes every shipped SDK test runner without accepting echoed commands", () => {
    const cases = [
      ["packages/android", "mvn -B -f packages/android/pom.xml test"],
      [
        "packages/csharp",
        "dotnet run --project packages/csharp/tests/Steward.Tests/Steward.Tests.csproj",
      ],
      ["packages/go", "go test ./..."],
      ["packages/java", "mvn -B -f packages/java/pom.xml test"],
      [
        "packages/python",
        "PYTHONPATH=packages/python python3 -m unittest discover -s packages/python/tests",
      ],
      [
        "packages/ruby",
        `ruby -Ipackages/ruby/lib -e 'Dir["packages/ruby/test/**/*_test.rb"].each { |file| require file }'`,
      ],
      ["packages/rust", "cargo test --locked --manifest-path packages/rust/Cargo.toml"],
      ["packages/swift", "swift test --package-path packages/swift"],
    ] as const;
    for (const [target, command] of cases) {
      const job = [
        "  dedicated:",
        "    steps:",
        "      - name: Test SDK",
        `        working-directory: ${target}`,
        `        run: ${command}`,
      ].join("\n");
      expect(jobExecutesPackageTests(extractJob(job, "dedicated"), target)).toBe(true);
      const echoed = [
        "  dedicated:",
        "    steps:",
        "      - name: Echo only",
        `        working-directory: ${target}`,
        `        run: echo ${command}`,
      ].join("\n");
      expect(jobExecutesPackageTests(extractJob(echoed, "dedicated"), target)).toBe(false);
    }
  });

  test("rejects adversarial environment prefixes without regex backtracking", () => {
    const command = `A=${'"" A='.repeat(20_000)}! echo packages/a`;
    const job = ["  dedicated:", "    steps:", `      - run: ${command}`].join("\n");
    expect(jobExecutesPackageTests(extractJob(job, "dedicated"), "packages/a")).toBe(false);
  });

  test("parses multiple quoted environment assignments and fails closed on malformed prefixes", () => {
    const jobFor = (command: string) =>
      extractJob(
        [
          "  dedicated:",
          "    steps:",
          "      - name: Test package",
          `        run: ${command}`,
        ].join("\n"),
        "dedicated",
      );
    expect(
      jobExecutesPackageTests(
        jobFor(`A="value with spaces" B='other value' bun test packages/a`),
        "packages/a",
      ),
    ).toBe(true);
    expect(
      jobExecutesPackageTests(jobFor(`A="unterminated bun test packages/a`), "packages/a"),
    ).toBe(false);
    expect(jobExecutesPackageTests(jobFor(`A= bun test packages/a`), "packages/a")).toBe(false);
    expect(
      jobExecutesPackageTests(jobFor(`A="value" echo bun test packages/a`), "packages/a"),
    ).toBe(false);
  });

  test("does not accept Ruby filename lookalikes as test commands", () => {
    for (const command of [
      "ruby packages/ruby/test/security_test.rbx packages/ruby",
      "ruby contest/security_test.rb packages/ruby",
    ]) {
      const job = extractJob(
        [
          "  dedicated:",
          "    steps:",
          "      - name: Test package",
          `        run: ${command}`,
        ].join("\n"),
        "dedicated",
      );
      expect(jobExecutesPackageTests(job, "packages/ruby")).toBe(false);
    }
  });

  test("ignores runner words and package paths in shell comments", () => {
    const job = extractJob(
      [
        "  dedicated:",
        "    steps:",
        "      - name: Test package",
        "        run: bun --help # test packages/a",
      ].join("\n"),
      "dedicated",
    );
    expect(jobExecutesPackageTests(job, "packages/a")).toBe(false);
  });
});
