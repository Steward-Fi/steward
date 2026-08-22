#!/usr/bin/env bun
import { existsSync } from "node:fs";

const requiredFiles = [
  "packages/flutter/pubspec.yaml",
  "packages/flutter/README.md",
  "packages/flutter/lib/steward.dart",
  "packages/flutter/lib/src/client.dart",
  "packages/flutter/lib/src/auth.dart",
  "packages/flutter/lib/src/models.dart",
  "packages/flutter/lib/src/storage.dart",
  "packages/flutter/lib/src/base_url.dart",
  "packages/flutter/test/steward_contract_test.dart",
  "packages/flutter/example/secure_session_storage.dart",
];

const failures: string[] = [];

for (const file of requiredFiles) {
  if (!existsSync(file)) failures.push(`missing file: ${file}`);
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Flutter SDK artifact check passed (${requiredFiles.length} files)`);
