import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { StewardClient } from "@stwd/sdk";
import type {
  StewardProviderProps,
  StewardContextValue,
  TenantControlPlaneConfig,
  TenantFeatureFlags,
  TenantTheme,
} from "./types.js";
import { DEFAULT_THEME, mergeTheme, themeToCSS } from "./utils/theme.js";

const DEFAULT_FEATURES: TenantFeatureFlags = {
  showFundingQR: true,
  showTransactionHistory: true,
  showSpendDashboard: true,
  showPolicyControls: true,
  showApprovalQueue: true,
  showSecretManager: false,
  enableSolana: true,
  showChainSelector: false,
  allowAddressExport: true,
};

const StewardContext = createContext<StewardContextValue | null>(null);

/**
 * Provider that wraps all Steward components.
 * Creates internal context with client, agent ID, theme, and feature flags.
 */
export function StewardProvider({
  client,
  agentId,
  features: featureOverrides,
  theme: themeOverrides,
  pollInterval = 30000,
  children,
}: StewardProviderProps) {
  const [tenantConfig, setTenantConfig] = useState<TenantControlPlaneConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Attempt to fetch tenant config; gracefully handle if endpoint doesn't exist yet
  useEffect(() => {
    let cancelled = false;

    async function fetchConfig() {
      try {
        // The tenant config endpoint may not exist yet — that's fine.
        // Components will use defaults + prop overrides.
        const res = await fetch(`${(client as unknown as { baseUrl: string }).baseUrl || ""}/tenants/config`, {
          headers: { Accept: "application/json" },
        });
        if (res.ok && !cancelled) {
          const json = await res.json();
          if (json.ok && json.data) {
            setTenantConfig(json.data);
          }
        }
      } catch {
        // Tenant config API not available — use defaults
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    fetchConfig();
    return () => { cancelled = true; };
  }, [client]);

  const features = useMemo<TenantFeatureFlags>(() => {
    const base = tenantConfig?.features || DEFAULT_FEATURES;
    return { ...base, ...featureOverrides };
  }, [tenantConfig, featureOverrides]);

  const theme = useMemo<TenantTheme>(() => {
    const base = tenantConfig?.theme || DEFAULT_THEME;
    return mergeTheme(base, themeOverrides);
  }, [tenantConfig, themeOverrides]);

  const cssVars = useMemo(() => themeToCSS(theme), [theme]);

  const value = useMemo<StewardContextValue>(
    () => ({
      client,
      agentId,
      features,
      theme,
      tenantConfig,
      isLoading,
      pollInterval,
    }),
    [client, agentId, features, theme, tenantConfig, isLoading, pollInterval],
  );

  return (
    <StewardContext.Provider value={value}>
      <div className="stwd-root" style={cssVars as React.CSSProperties}>
        {children}
      </div>
    </StewardContext.Provider>
  );
}

/**
 * Access the Steward context. Must be used inside <StewardProvider>.
 */
export function useStewardContext(): StewardContextValue {
  const ctx = useContext(StewardContext);
  if (!ctx) {
    throw new Error("useStewardContext must be used within a <StewardProvider>");
  }
  return ctx;
}
