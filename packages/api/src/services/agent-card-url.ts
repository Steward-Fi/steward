import { validateWebhookUrlResolved } from "./webhook-url";

/** Validate the public HTTPS destination published in an ERC-8004 agent card. */
export async function validateAgentCardApiUrl(apiUrl: string): Promise<string | null> {
  if (!apiUrl) return null;
  const destinationError = await validateWebhookUrlResolved(apiUrl);
  if (destinationError) return `apiUrl ${destinationError}`;
  if (new URL(apiUrl).protocol !== "https:") return "apiUrl must use https";
  return null;
}
