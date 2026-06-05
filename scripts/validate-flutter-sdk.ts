#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";

const requiredFiles = [
  "packages/flutter/pubspec.yaml",
  "packages/flutter/README.md",
  "packages/flutter/lib/steward.dart",
  "packages/flutter/lib/src/client.dart",
  "packages/flutter/lib/src/auth.dart",
  "packages/flutter/lib/src/models.dart",
  "packages/flutter/lib/src/storage.dart",
  "packages/flutter/test/steward_contract_test.dart",
];

const requiredNeedles: Array<[string, string]> = [
  ["packages/flutter/pubspec.yaml", "name: steward_flutter"],
  ["packages/flutter/pubspec.yaml", "flutter:"],
  ["packages/flutter/lib/steward.dart", "export 'src/auth.dart';"],
  ["packages/flutter/lib/steward.dart", "export 'src/client.dart';"],
  ["packages/flutter/lib/src/client.dart", "X-Steward-Request-Timestamp"],
  ["packages/flutter/lib/src/client.dart", "X-Steward-Signature"],
  ["packages/flutter/lib/src/client.dart", "/user/me/push-subscriptions"],
  ["packages/flutter/lib/src/auth.dart", "/auth/email/send"],
  ["packages/flutter/lib/src/auth.dart", "/auth/sms/verify"],
  ["packages/flutter/lib/src/auth.dart", "/auth/whatsapp/verify"],
  ["packages/flutter/lib/src/auth.dart", "/auth/oauth/"],
  ["packages/flutter/lib/src/auth.dart", "OAuth state mismatch"],
  ["packages/flutter/lib/src/storage.dart", "abstract interface class StewardSessionStorage"],
  ["packages/flutter/test/steward_contract_test.dart", "NamespacedStewardSessionStorage"],
  ["packages/flutter/test/steward_contract_test.dart", "PushSubscriptionInput"],
];

const failures: string[] = [];

for (const file of requiredFiles) {
  if (!existsSync(file)) failures.push(`missing file: ${file}`);
}

for (const [file, needle] of requiredNeedles) {
  if (!existsSync(file)) continue;
  const source = readFileSync(file, "utf8");
  if (!source.includes(needle)) failures.push(`${file} missing ${JSON.stringify(needle)}`);
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Flutter SDK contract check passed (${requiredFiles.length} files)`);
