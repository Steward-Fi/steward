"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { createClient } from "@/lib/supabase";
import { setCredentials } from "@/lib/api";
import type { User, SupabaseClient } from "@supabase/supabase-js";

interface TenantInfo {
  tenantId: string;
  tenantName: string;
  apiKey: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  tenant: TenantInfo | null;
  supabase: SupabaseClient;
  loading: boolean;
  signOut: () => Promise<void>;
  refreshTenant: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [supabase] = useState(() => createClient());
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const loadTenant = useCallback(
    async (userId: string) => {
      const { data } = await supabase
        .from("steward_tenants")
        .select("tenant_id, tenant_name, api_key, role")
        .eq("user_id", userId)
        .order("created_at", { ascending: true })
        .limit(1)
        .single();

      if (data) {
        const t = {
          tenantId: data.tenant_id,
          tenantName: data.tenant_name,
          apiKey: data.api_key,
          role: data.role,
        };
        setTenant(t);
        setCredentials(t.tenantId, t.apiKey);
      } else {
        setTenant(null);
      }
    },
    [supabase],
  );

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      const u = session?.user ?? null;
      setUser(u);
      if (u) {
        loadTenant(u.id).finally(() => setLoading(false));
      } else {
        setLoading(false);
      }
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      const u = session?.user ?? null;
      setUser(u);
      if (u) {
        loadTenant(u.id);
      } else {
        setTenant(null);
      }
    });

    return () => subscription.unsubscribe();
  }, [supabase, loadTenant]);

  const signOut = async () => {
    await supabase.auth.signOut();
    setUser(null);
    setTenant(null);
  };

  const refreshTenant = async () => {
    if (user) await loadTenant(user.id);
  };

  return (
    <AuthContext.Provider
      value={{ user, tenant, supabase, loading, signOut, refreshTenant }}
    >
      {children}
    </AuthContext.Provider>
  );
}
