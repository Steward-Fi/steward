import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;
const STEWARD_API_URL = process.env.STEWARD_API_URL || "https://api.steward.fi";
const STEWARD_ADMIN_KEY = process.env.STEWARD_ADMIN_KEY || "";

export async function POST(req: NextRequest) {
  try {
    // Verify the user is authenticated via Supabase
    const authHeader = req.headers.get("authorization");
    const token =
      authHeader?.replace("Bearer ", "") ||
      req.cookies.get("sb-xuxlhmsvbsgichrvvapv-auth-token")?.value;

    // Create a supabase client to verify the user
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // Get user from the auth token in cookies
    // For browser-based auth, we need to extract from the cookie
    const cookieHeader = req.headers.get("cookie") || "";
    const accessTokenMatch = cookieHeader.match(
      /sb-xuxlhmsvbsgichrvvapv-auth-token\.0=([^;]+)/,
    );

    let userId: string | null = null;

    if (token) {
      const {
        data: { user },
      } = await supabase.auth.getUser(token);
      userId = user?.id || null;
    }

    if (!userId && accessTokenMatch) {
      // Try to decode from chunked cookie
      const {
        data: { user },
      } = await supabase.auth.getUser(
        decodeURIComponent(accessTokenMatch[1]),
      );
      userId = user?.id || null;
    }

    // If we still don't have a user, try getting from the request body context
    // The client-side sends the request with cookies automatically
    if (!userId) {
      // Last resort: check all cookies for supabase auth
      const allCookies = Object.fromEntries(
        cookieHeader.split(";").map((c) => {
          const [k, ...v] = c.trim().split("=");
          return [k, v.join("=")];
        }),
      );

      for (const [key, value] of Object.entries(allCookies)) {
        if (key.includes("auth-token") && value) {
          try {
            const {
              data: { user },
            } = await supabase.auth.getUser(decodeURIComponent(value));
            if (user) {
              userId = user.id;
              break;
            }
          } catch {
            continue;
          }
        }
      }
    }

    if (!userId) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 },
      );
    }

    const body = await req.json();
    const { tenantId, tenantName } = body;

    if (!tenantId || !tenantName) {
      return NextResponse.json(
        { error: "tenantId and tenantName are required" },
        { status: 400 },
      );
    }

    // Generate a raw API key
    const rawApiKey = `stw_${crypto.randomBytes(24).toString("hex")}`;

    // Create tenant in Steward API
    const stewardRes = await fetch(`${STEWARD_API_URL}/tenants`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(STEWARD_ADMIN_KEY
          ? {
              "X-Steward-Tenant": "default",
              "X-Steward-Key": STEWARD_ADMIN_KEY,
            }
          : {}),
      },
      body: JSON.stringify({
        id: tenantId,
        name: tenantName,
        apiKeyHash: rawApiKey, // API will hash it
      }),
    });

    if (!stewardRes.ok) {
      const err = await stewardRes.json().catch(() => ({}));
      return NextResponse.json(
        {
          error:
            (err as { error?: string }).error || "Failed to create tenant",
        },
        { status: stewardRes.status },
      );
    }

    return NextResponse.json({ apiKey: rawApiKey, tenantId });
  } catch (err: unknown) {
    console.error("Provision error:", err);
    return NextResponse.json(
      {
        error:
          err instanceof Error ? err.message : "Internal server error",
      },
      { status: 500 },
    );
  }
}
