import { isPersistedPolicyType } from "@stwd/db";
import type { PolicyRule } from "@stwd/shared";

const CONDITION_FIELDS = new Set([
  "to",
  "ethereum_transaction.to",
  "ethereum_transaction.chain_id",
  "ethereum_transaction.value",
  "ethereum_transaction.data",
  "solana_system_program_instruction.Transfer.to",
  "chain_id",
  "value",
  "data",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const MAX_UINT256_DECIMAL =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const MAX_UINT256_DECIMAL_DIGITS = 78;

function isWeiString(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return false;
  const normalized = value.replace(/^0+/, "") || "0";
  if (normalized.length > MAX_UINT256_DECIMAL_DIGITS) return false;
  return normalized.length < MAX_UINT256_DECIMAL_DIGITS || normalized <= MAX_UINT256_DECIMAL;
}

function isPositiveFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function isEvmAddress(value: unknown): value is string {
  return typeof value === "string" && /^0x[a-fA-F0-9]{40}$/.test(value);
}

function isEvmSelector(value: unknown): value is string {
  return typeof value === "string" && /^0x[a-fA-F0-9]{8}$/.test(value);
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

function areOptionalEvmAddresses(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.every(isEvmAddress));
}

function validatePolicyConfig(policy: PolicyRule): string | null {
  const config = policy.config;

  switch (policy.type) {
    case "spending-limit": {
      const weiFields = ["maxPerTx", "maxPerDay", "maxPerWeek"] as const;
      const usdFields = ["maxPerTxUsd", "maxPerDayUsd", "maxPerWeekUsd"] as const;
      for (const field of weiFields) {
        if (config[field] !== undefined && !isWeiString(config[field])) {
          return `spending-limit.${field} must be a wei string`;
        }
      }
      for (const field of usdFields) {
        if (config[field] !== undefined && !isPositiveFiniteNumber(config[field])) {
          return `spending-limit.${field} must be a positive number`;
        }
      }
      const hasWeiLimit = weiFields.some((field) => isWeiString(config[field]));
      const hasUsdLimit = usdFields.some((field) => isPositiveFiniteNumber(config[field]));
      if (!hasWeiLimit && !hasUsdLimit) {
        return "spending-limit requires at least one positive wei or USD limit";
      }
      return null;
    }

    case "approved-addresses":
      if (!Array.isArray(config.addresses) || !config.addresses.every(isEvmAddress)) {
        return "approved-addresses.addresses must be an array of EVM addresses";
      }
      if (config.mode !== "whitelist" && config.mode !== "blacklist") {
        return "approved-addresses.mode must be whitelist or blacklist";
      }
      return null;

    case "auto-approve-threshold":
      if (!isWeiString(config.threshold) && !isPositiveFiniteNumber(config.thresholdUsd)) {
        return "auto-approve-threshold requires threshold or thresholdUsd";
      }
      if (config.threshold !== undefined && !isWeiString(config.threshold)) {
        return "auto-approve-threshold.threshold must be a wei string";
      }
      if (config.thresholdUsd !== undefined && !isPositiveFiniteNumber(config.thresholdUsd)) {
        return "auto-approve-threshold.thresholdUsd must be a positive number";
      }
      return null;

    case "time-window":
      if (
        !Array.isArray(config.allowedHours) ||
        !config.allowedHours.every(
          (window) =>
            isPlainObject(window) &&
            Number.isInteger(window.start) &&
            Number.isInteger(window.end) &&
            Number(window.start) >= 0 &&
            Number(window.start) <= 23 &&
            Number(window.end) >= 0 &&
            Number(window.end) <= 23,
        )
      ) {
        return "time-window.allowedHours must contain UTC hour windows";
      }
      if (
        !Array.isArray(config.allowedDays) ||
        !config.allowedDays.every((day) => Number.isInteger(day) && day >= 0 && day <= 6)
      ) {
        return "time-window.allowedDays must contain weekdays 0-6";
      }
      return null;

    case "rate-limit":
      if (!isPositiveInteger(config.maxTxPerHour) || !isPositiveInteger(config.maxTxPerDay)) {
        return "rate-limit requires positive integer maxTxPerHour and maxTxPerDay";
      }
      return null;

    case "allowed-chains":
      if (
        !Array.isArray(config.chains) ||
        config.chains.length === 0 ||
        !config.chains.every((chain) => typeof chain === "string" && chain.trim().length > 0)
      ) {
        return "allowed-chains.chains must be a non-empty string array";
      }
      return null;

    case "condition-set":
      if (typeof config.conditionSetId !== "string" || config.conditionSetId.trim() === "") {
        return "condition-set.conditionSetId is required";
      }
      if (!isUuid(config.conditionSetId)) {
        return "condition-set.conditionSetId must be a UUID";
      }
      if (config.field !== undefined && !CONDITION_FIELDS.has(String(config.field))) {
        return "condition-set.field is invalid";
      }
      if (
        config.operator !== undefined &&
        config.operator !== "in_condition_set" &&
        config.operator !== "not_in_condition_set"
      ) {
        return "condition-set.operator is invalid";
      }
      if (config.caseSensitive !== undefined && typeof config.caseSensitive !== "boolean") {
        return "condition-set.caseSensitive must be a boolean";
      }
      return null;

    case "contract-allowlist":
      if (
        !Array.isArray(config.contracts) ||
        config.contracts.length === 0 ||
        !config.contracts.every((contract) => {
          if (
            !isPlainObject(contract) ||
            !isEvmAddress(contract.address) ||
            !Array.isArray(contract.selectors) ||
            contract.selectors.length === 0 ||
            !contract.selectors.every(isEvmSelector)
          ) {
            return false;
          }
          if (contract.constraints === undefined) return true;
          if (!isPlainObject(contract.constraints)) return false;
          const selectors = new Set(contract.selectors.map((selector) => selector.toLowerCase()));
          return Object.entries(contract.constraints).every(([selector, constraint]) => {
            if (!isEvmSelector(selector) || !selectors.has(selector.toLowerCase())) return false;
            if (!isPlainObject(constraint)) return false;
            return (
              areOptionalEvmAddresses(constraint.recipientAllowlist) &&
              areOptionalEvmAddresses(constraint.recipientBlocklist) &&
              areOptionalEvmAddresses(constraint.spenderAllowlist) &&
              areOptionalEvmAddresses(constraint.spenderBlocklist) &&
              areOptionalEvmAddresses(constraint.fromAllowlist) &&
              areOptionalEvmAddresses(constraint.fromBlocklist) &&
              (constraint.maxAmount === undefined || isWeiString(constraint.maxAmount))
            );
          });
        })
      ) {
        return "contract-allowlist.contracts must be non-empty entries with EVM address, 4-byte selectors, and valid selector constraints";
      }
      return null;

    case "reputation-threshold":
      if (
        typeof config.minScore !== "number" ||
        !Number.isFinite(config.minScore) ||
        config.minScore < 0 ||
        config.minScore > 100
      ) {
        return "reputation-threshold.minScore must be a number from 0-100";
      }
      if (!["approve", "require-approval", "block"].includes(String(config.action))) {
        return "reputation-threshold.action is invalid";
      }
      if (!["internal", "onchain", "combined"].includes(String(config.source))) {
        return "reputation-threshold.source is invalid";
      }
      if (!["approve", "require-approval", "block"].includes(String(config.fallbackAction))) {
        return "reputation-threshold.fallbackAction is invalid";
      }
      return null;

    case "reputation-scaling":
      if (!isWeiString(config.baseMaxPerTx) || !isWeiString(config.maxMaxPerTx)) {
        return "reputation-scaling requires baseMaxPerTx and maxMaxPerTx wei strings";
      }
      if (BigInt(config.maxMaxPerTx) < BigInt(config.baseMaxPerTx)) {
        return "reputation-scaling.maxMaxPerTx must be greater than or equal to baseMaxPerTx";
      }
      if (config.curve !== "linear" && config.curve !== "logarithmic") {
        return "reputation-scaling.curve must be linear or logarithmic";
      }
      return null;

    case "venue-allowlist":
      if (
        !Array.isArray(config.allowedVenues) ||
        config.allowedVenues.length === 0 ||
        !config.allowedVenues.every((venue) => typeof venue === "string" && venue.trim())
      ) {
        return "venue-allowlist.allowedVenues must be a non-empty string array";
      }
      return null;

    case "leverage-cap":
      if (!isPositiveFiniteNumber(config.maxLeverage)) {
        return "leverage-cap.maxLeverage must be a positive number";
      }
      return null;

    default:
      return `Unknown policy type "${policy.type}"`;
  }
}

export function validatePolicyRule(policy: unknown): policy is PolicyRule {
  return getPolicyRuleValidationError(policy) === null;
}

const MAX_POLICY_RULES = 50;
const MAX_POLICY_RULES_BYTES = 65_536;

export function getPolicyRuleValidationError(policy: unknown): string | null {
  if (!isPlainObject(policy)) return "Each policy must be an object";
  if (typeof policy.type !== "string" || policy.type.trim() === "") {
    return "Each policy must have a non-empty 'type' field";
  }
  if (!isPersistedPolicyType(policy.type)) {
    return `Unknown policy type "${policy.type}"`;
  }
  if (typeof policy.enabled !== "boolean") {
    return `Policy "${String(policy.id || policy.type)}": enabled must be a boolean`;
  }
  if (!isPlainObject(policy.config)) {
    return `Policy "${String(policy.id || policy.type)}": config must be an object`;
  }
  return validatePolicyConfig(policy as unknown as PolicyRule);
}

export function getPolicyRulesValidationError(policies: unknown[]): string | null {
  if (policies.length > MAX_POLICY_RULES) {
    return `Policy list cannot contain more than ${MAX_POLICY_RULES} rules`;
  }
  if (JSON.stringify(policies).length > MAX_POLICY_RULES_BYTES) {
    return `Policy list cannot exceed ${MAX_POLICY_RULES_BYTES} bytes`;
  }

  const ids = new Set<string>();
  const singletonTypes = new Set<string>();
  for (const policy of policies) {
    const error = getPolicyRuleValidationError(policy);
    if (error) return error;
    if (isPlainObject(policy) && typeof policy.id === "string" && policy.id.trim()) {
      if (ids.has(policy.id)) return `Duplicate policy id "${policy.id}"`;
      ids.add(policy.id);
    }
    if (
      isPlainObject(policy) &&
      policy.enabled !== false &&
      policy.type === "auto-approve-threshold"
    ) {
      if (singletonTypes.has(policy.type)) return `Duplicate policy type "${policy.type}"`;
      singletonTypes.add(policy.type);
    }
  }
  return null;
}
