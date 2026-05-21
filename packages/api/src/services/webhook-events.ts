import type { WebhookEventType } from "@stwd/shared";

export const CONFIGURED_WEBHOOK_EVENT_TYPES = [
  "tx.pending",
  "tx.approved",
  "tx.denied",
  "tx.signed",
  "spend.threshold",
  "policy.violation",
] as const satisfies readonly WebhookEventType[];

export type ConfiguredWebhookEventType = (typeof CONFIGURED_WEBHOOK_EVENT_TYPES)[number];
type VaultWebhookEventAlias = Extract<
  WebhookEventType,
  "approval_required" | "tx_signed" | "tx_confirmed" | "tx_failed" | "tx_rejected"
>;

export type DispatchableWebhookEventType = WebhookEventType;

const CONFIGURED_EVENT_SET = new Set<string>(CONFIGURED_WEBHOOK_EVENT_TYPES);
const VAULT_EVENT_ALIAS_MAP: Partial<Record<VaultWebhookEventAlias, ConfiguredWebhookEventType>> = {
  approval_required: "tx.pending",
  tx_signed: "tx.signed",
  tx_rejected: "policy.violation",
};

export function toConfiguredWebhookEventType(
  type: DispatchableWebhookEventType,
): ConfiguredWebhookEventType | null {
  if (CONFIGURED_EVENT_SET.has(type as WebhookEventType)) {
    return type as ConfiguredWebhookEventType;
  }
  return VAULT_EVENT_ALIAS_MAP[type as VaultWebhookEventAlias] ?? null;
}

export function acceptsConfiguredWebhookEvent(
  events: string[],
  type: ConfiguredWebhookEventType,
): boolean {
  return events.length === 0 || events.includes(type);
}
