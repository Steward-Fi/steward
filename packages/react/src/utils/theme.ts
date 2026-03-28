import type { TenantTheme } from "../types.js";

export const DEFAULT_THEME: TenantTheme = {
  primaryColor: "#8B5CF6",
  accentColor: "#A78BFA",
  backgroundColor: "#0F0F0F",
  surfaceColor: "#1A1A2E",
  textColor: "#FAFAFA",
  mutedColor: "#6B7280",
  successColor: "#10B981",
  errorColor: "#EF4444",
  warningColor: "#F59E0B",
  borderRadius: 12,
  fontFamily: "Inter, system-ui, sans-serif",
  colorScheme: "dark",
};

export function themeToCSS(theme: TenantTheme): Record<string, string> {
  return {
    "--stwd-primary": theme.primaryColor,
    "--stwd-accent": theme.accentColor,
    "--stwd-bg": theme.backgroundColor,
    "--stwd-surface": theme.surfaceColor,
    "--stwd-text": theme.textColor,
    "--stwd-muted": theme.mutedColor,
    "--stwd-success": theme.successColor,
    "--stwd-error": theme.errorColor,
    "--stwd-warning": theme.warningColor,
    "--stwd-radius": `${theme.borderRadius}px`,
    "--stwd-font": theme.fontFamily || "Inter, system-ui, sans-serif",
  };
}

export function mergeTheme(base: TenantTheme, overrides?: Partial<TenantTheme>): TenantTheme {
  if (!overrides) return base;
  return { ...base, ...overrides };
}
