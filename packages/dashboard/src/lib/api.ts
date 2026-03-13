import { StewardClient } from "./steward-client";

const API_URL = process.env.NEXT_PUBLIC_STEWARD_API_URL || "http://localhost:3200";
const API_KEY = process.env.NEXT_PUBLIC_STEWARD_API_KEY || "";
const TENANT_ID = process.env.NEXT_PUBLIC_STEWARD_TENANT_ID || "default";

export const steward = new StewardClient({
  baseUrl: API_URL,
  apiKey: API_KEY,
  tenantId: TENANT_ID,
});

export { API_URL, API_KEY, TENANT_ID };
