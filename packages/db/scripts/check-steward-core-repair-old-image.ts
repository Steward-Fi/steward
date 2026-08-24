import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export const STEWARD_PRODUCTION_ROLLBACK_IMAGE =
  "ghcr.io/steward-fi/steward@sha256:51557626b6c3215d432c7f4077b1cf44a059051d5a763384335a88270b371ca1";
export const STEWARD_PRODUCTION_ROLLBACK_SOURCE = "a7b1b4d5232a234e0e3e86e600f58ef9ce8f68ad";
export const STEWARD_CORE_REPAIR_CATALOG_SHA256 =
  "440545f35aed2d0470a654d1c2a0976b928c835241b282258867888b52ee820c";

const REQUIRED_PROBES = [
  "health",
  "ready",
  "providerDiscovery",
  "emailSession",
  "passkeySession",
  "sessionRefresh",
  "chatWrite",
] as const;

type CompatibilityProbe = (typeof REQUIRED_PROBES)[number];
type CompatibilityReceipt = {
  proofVersion: number;
  databaseClass: string;
  productionDatabaseTouched: boolean;
  targetSchema: string;
  repairVersion: string;
  catalogManifestSha256: string;
  oldImage: {
    image: string;
    sourceCommit: string;
    automaticMigrationsDisabled: boolean;
  };
  candidateImage: {
    image: string;
    sourceCommit: string;
    automaticMigrationsDisabled: boolean;
  };
  preRepair: Partial<Record<CompatibilityProbe, string>>;
  postRepair: Partial<Record<CompatibilityProbe, string>>;
  providerExecution: {
    drainedBeforeRepair: boolean;
    legacyResume: string;
    candidateEvidenceResumeAndExecution: string;
    rollbackMode: string;
  };
  reviewedBy: string;
  evidenceArtifactSha256: string;
};

export type StewardCoreRepairExpectedCandidate = {
  image: string;
  sourceCommit: string;
  evidenceArtifactSha256: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseReceipt(value: unknown): CompatibilityReceipt {
  if (!isRecord(value)) throw new Error("old-image compatibility receipt must be an object");
  return value as CompatibilityReceipt;
}

/**
 * Validate an externally captured, non-production compatibility receipt.
 * Catalog success alone never satisfies this gate. The legacy governed-action
 * resume is expected to fail closed after 0084, so an accepted receipt also
 * proves the forward-only rollback limitation and a candidate evidence write.
 */
export function validateStewardCoreRepairOldImageReceipt(
  value: unknown,
  expectedCandidate: StewardCoreRepairExpectedCandidate,
): CompatibilityReceipt {
  const receipt = parseReceipt(value);
  if (
    receipt.proofVersion !== 1 ||
    receipt.databaseClass !== "isolated-production-restore" ||
    receipt.productionDatabaseTouched !== false ||
    receipt.targetSchema !== "steward" ||
    receipt.repairVersion !== "prod-core-0082-0110-v1" ||
    receipt.catalogManifestSha256 !== STEWARD_CORE_REPAIR_CATALOG_SHA256
  ) {
    throw new Error("old-image compatibility receipt does not match the reviewed repair target");
  }
  if (
    receipt.oldImage?.image !== STEWARD_PRODUCTION_ROLLBACK_IMAGE ||
    receipt.oldImage?.sourceCommit !== STEWARD_PRODUCTION_ROLLBACK_SOURCE ||
    receipt.oldImage?.automaticMigrationsDisabled !== true
  ) {
    throw new Error("old-image compatibility receipt does not pin the production rollback image");
  }
  if (
    !/^ghcr\.io\/steward-fi\/steward@sha256:[0-9a-f]{64}$/.test(expectedCandidate.image) ||
    !/^[0-9a-f]{40}$/.test(expectedCandidate.sourceCommit) ||
    !/^sha256:[0-9a-f]{64}$/.test(expectedCandidate.evidenceArtifactSha256)
  ) {
    throw new Error("approved candidate or evidence binding is missing or malformed");
  }
  if (
    receipt.candidateImage?.image !== expectedCandidate.image ||
    receipt.candidateImage?.sourceCommit !== expectedCandidate.sourceCommit ||
    receipt.candidateImage?.automaticMigrationsDisabled !== true
  ) {
    throw new Error("old-image compatibility receipt does not pin the approved candidate image");
  }
  for (const probe of REQUIRED_PROBES) {
    if (receipt.preRepair?.[probe] !== "pass" || receipt.postRepair?.[probe] !== "pass") {
      throw new Error(
        `old-image compatibility probe ${probe} is not green before and after repair`,
      );
    }
  }
  if (
    receipt.providerExecution?.drainedBeforeRepair !== true ||
    receipt.providerExecution?.legacyResume !== "blocked_by_0084_authority_fence" ||
    receipt.providerExecution?.candidateEvidenceResumeAndExecution !== "pass" ||
    receipt.providerExecution?.rollbackMode !==
      "forward_only_old_image_requires_provider_execution_drain"
  ) {
    throw new Error("old-image compatibility receipt does not prove the governed-action boundary");
  }
  const reviewer = receipt.reviewedBy?.trim().toLowerCase();
  if (!reviewer || reviewer === "wakesync") {
    throw new Error("old-image compatibility receipt requires an independent reviewer");
  }
  if (receipt.evidenceArtifactSha256 !== expectedCandidate.evidenceArtifactSha256) {
    throw new Error("old-image compatibility evidence artifact hash does not match the file");
  }
  return receipt;
}

function sha256File(path: string): string {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

const isEntrypoint = process.argv[1] === new URL(import.meta.url).pathname;

if (isEntrypoint) {
  const receiptPath = process.env.STEWARD_CORE_REPAIR_OLD_IMAGE_RECEIPT;
  const candidateImage = process.env.STEWARD_CORE_REPAIR_CANDIDATE_IMAGE;
  const candidateSource = process.env.STEWARD_CORE_REPAIR_CANDIDATE_SOURCE;
  const evidencePath = process.env.STEWARD_CORE_REPAIR_OLD_IMAGE_EVIDENCE;
  if (!receiptPath || !candidateImage || !candidateSource || !evidencePath) {
    console.error(
      "NO-GO: receipt, exact candidate image/source, and evidence artifact are required; " +
        "catalog checks alone do not authorize production",
    );
    process.exitCode = 1;
  } else {
    try {
      const receipt = validateStewardCoreRepairOldImageReceipt(
        JSON.parse(readFileSync(receiptPath, "utf8")),
        {
          image: candidateImage,
          sourceCommit: candidateSource,
          evidenceArtifactSha256: sha256File(evidencePath),
        },
      );
      console.log(
        `Old-image forward-only compatibility gate passed for ${receipt.oldImage.sourceCommit}; ` +
          "provider execution must remain drained during any rollback to that image.",
      );
    } catch (error) {
      console.error(
        `NO-GO: ${error instanceof Error ? error.message : "invalid old-image compatibility receipt"}`,
      );
      process.exitCode = 1;
    }
  }
}
