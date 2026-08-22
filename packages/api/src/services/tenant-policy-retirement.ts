export const TENANT_DEFAULT_POLICIES_RETIREMENT = Object.freeze({
  status: 410 as const,
  error:
    "defaultPolicies are retired because process-local tenant policy state is not durable; use /policies and durable per-agent policy assignments instead",
});
