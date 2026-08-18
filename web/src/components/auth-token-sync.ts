export interface LegacyAuthTokenSyncInput {
  isAuthenticated: boolean;
  sessionToken: string | null;
  lastToken: string | null;
  getToken: () => string | null;
  setToken: (token: string) => void;
  clearToken: () => void;
}

/** Applies an auth state change to the legacy API client and returns the new sync state. */
export function syncLegacyAuthToken(input: LegacyAuthTokenSyncInput): string | null {
  if (!input.isAuthenticated) {
    input.clearToken();
    return null;
  }

  const token = input.sessionToken ?? input.getToken();
  if (token && token !== input.lastToken) {
    input.setToken(token);
    return token;
  }
  return input.lastToken;
}
