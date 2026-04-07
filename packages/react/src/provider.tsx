import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  useCallback,
} from "react";
import type { StewardClient } from "@stwd/sdk";
import { StewardAuth } from "@stwd/sdk";
import type {
  StewardProviderProps,
  StewardContextValue,
  TenantControlPlaneConfig,
  TenantFeatureFlags,
  TenantTheme,
  StewardAuthConfig,
  StewardAuthContextValue,
} from "./types.js";
import type { StewardUser, StewardSession, SessionStorage } from "@stwd/sdk";
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

// ─── Contexts ────────────────────────────────────────────────────────────────

const StewardContext = createContext<StewardContextValue | null>(null);

/**
 * Auth context — only populated when <StewardProvider auth={...}> is provided.
 * Consumers should use useAuth() hook which throws a helpful error when missing.
 */
export const StewardAuthContext = createContext<StewardAuthContextValue | null>(null);

// ─── Extended Provider Props ─────────────────────────────────────────────────

export interface StewardProviderWithAuthProps extends StewardProviderProps {
  /**
   * Optional auth configuration. When provided, StewardProvider creates a
   * StewardAuth instance and exposes auth state via useAuth().
   *
   * @example
   * <StewardProvider
   *   client={client}
   *   agentId="abc"
   *   auth={{ baseUrl: "https://api.steward.fi" }}
   * >
   *   <App />
   * </StewardProvider>
   */
  auth?: StewardAuthConfig;
}

// ─── Provider ────────────────────────────────────────────────────────────────

/**
 * Provider that wraps all Steward components.
 * Creates internal context with client, agent ID, theme, and feature flags.
 * Optionally manages auth state when `auth` prop is provided.
 */
export function StewardProvider({
  client,
  agentId,
  features: featureOverrides,
  theme: themeOverrides,
  pollInterval = 30000,
  auth: authConfig,
  children,
}: StewardProviderWithAuthProps) {
  const [tenantConfig, setTenantConfig] = useState<TenantControlPlaneConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // ─── Auth state ────────────────────────────────────────────────────────────

  const authInstance = useMemo<StewardAuth | null>(() => {
    if (!authConfig) return null;
    return new StewardAuth({
      baseUrl: authConfig.baseUrl,
      storage: authConfig.storage,
    });
  }, [authConfig?.baseUrl, authConfig?.storage]);

  const [authSession, setAuthSession] = useState<StewardSession | null>(
    () => authInstance?.getSession() ?? null,
  );
  const [authLoading, setAuthLoading] = useState(false);

  // Subscribe to session changes from the StewardAuth instance
  useEffect(() => {
    if (!authInstance) return;
    // Sync initial session
    setAuthSession(authInstance.getSession());
    // Subscribe to future changes
    const unsubscribe = authInstance.onSessionChange((session) => {
      setAuthSession(session);
    });
    return unsubscribe;
  }, [authInstance]);

  const signOut = useCallback(() => {
    authInstance?.signOut();
  }, [authInstance]);

  const getToken = useCallback((): string | null => {
    return authInstance?.getToken() ?? null;
  }, [authInstance]);

  const signInWithPasskey = useCallback(async (email: string) => {
    if (!authInstance) throw new Error("StewardProvider: auth prop not configured");
    setAuthLoading(true);
    try {
      return await authInstance.signInWithPasskey(email);
    } finally {
      setAuthLoading(false);
    }
  }, [authInstance]);

  const signInWithEmail = useCallback(async (email: string) => {
    if (!authInstance) throw new Error("StewardProvider: auth prop not configured");
    return authInstance.signInWithEmail(email);
  }, [authInstance]);

  const verifyEmailCallback = useCallback(async (token: string, email: string) => {
    if (!authInstance) throw new Error("StewardProvider: auth prop not configured");
    setAuthLoading(true);
    try {
      return await authInstance.verifyEmailCallback(token, email);
    } finally {
      setAuthLoading(false);
    }
  }, [authInstance]);

  const signInWithSIWE = useCallback(async (address: string, signMessage: (msg: string) => Promise<string>) => {
    if (!authInstance) throw new Error("StewardProvider: auth prop not configured");
    setAuthLoading(true);
    try {
      return await authInstance.signInWithSIWE(address, signMessage);
    } finally {
      setAuthLoading(false);
    }
  }, [authInstance]);

  const authContextValue = useMemo<StewardAuthContextValue | null>(() => {
    if (!authInstance) return null;
    return {
      isAuthenticated: authSession !== null,
      isLoading: authLoading,
      user: authSession?.user ?? null,
      session: authSession,
      signOut,
      getToken,
      signInWithPasskey,
      signInWithEmail,
      verifyEmailCallback,
      signInWithSIWE,
    };
  }, [authInstance, authSession, authLoading, signOut, getToken, signInWithPasskey, signInWithEmail, verifyEmailCallback, signInWithSIWE]);

  // ─── Tenant config ─────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function fetchConfig() {
      try {
        const res = await fetch(
          `${(client as unknown as { baseUrl: string }).baseUrl || ""}/tenants/config`,
          { headers: { Accept: "application/json" } },
        );
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
    return () => {
      cancelled = true;
    };
  }, [client]);

  // ─── Theme & features ──────────────────────────────────────────────────────

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

  // ─── Render ────────────────────────────────────────────────────────────────

  const inner = (
    <StewardContext.Provider value={value}>
      <div className="stwd-root" style={cssVars as React.CSSProperties}>
        {children}
      </div>
    </StewardContext.Provider>
  );

  if (authContextValue) {
    return (
      <StewardAuthContext.Provider value={authContextValue}>
        {inner}
      </StewardAuthContext.Provider>
    );
  }

  return inner;
}

// ─── Context hooks ────────────────────────────────────────────────────────────

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
