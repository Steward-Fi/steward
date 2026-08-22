import { closeDb } from "@stwd/db";
import { checkCapabilityRateLimitReadiness } from "../../services/capability-rate-limit-readiness";

try {
  console.log(JSON.stringify(await checkCapabilityRateLimitReadiness()));
} finally {
  await closeDb();
}

// Importing API context installs process-lifetime maintenance resources.
process.exit(0);
