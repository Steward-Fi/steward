/**
 * GENERATED FILE — do not edit by hand.
 * Produced by packages/api/scripts/generate-sdk-types.ts from the OpenAPI
 * document (packages/api/openapi.json). Run `bun run openapi:generate` in
 * @stwd/api to regenerate after a route schema changes.
 */

export interface paths {
    "/dashboard/{agentId}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Aggregated agent dashboard (identity, balances, spend, policies, approvals, recent txs) */
        get: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    agentId: string;
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Aggregated dashboard for the agent */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": {
                            /** @enum {boolean} */
                            ok: true;
                            data: components["schemas"]["AgentDashboard"];
                        };
                    };
                };
                /** @description Tenant-level auth or recent MFA required */
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ErrorResponse"];
                    };
                };
                /** @description Agent not found */
                404: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ErrorResponse"];
                    };
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/trade/token-status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Agent trade-token expiry status */
        get: {
            parameters: {
                query?: {
                    agentId?: string;
                };
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Observed or unknown token status for the agent */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": {
                            /** @enum {boolean} */
                            ok: true;
                            data: components["schemas"]["TradeTokenStatus"];
                        };
                    };
                };
                /** @description agentId is required */
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ErrorResponse"];
                    };
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/trade/token-status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Agent trade-token expiry status */
        get: {
            parameters: {
                query?: {
                    agentId?: string;
                };
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                /** @description Observed or unknown token status for the agent */
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": {
                            /** @enum {boolean} */
                            ok: true;
                            data: components["schemas"]["TradeTokenStatus"];
                        };
                    };
                };
                /** @description agentId is required */
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["ErrorResponse"];
                    };
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        AgentDashboard: {
            agent: components["schemas"]["AgentIdentitySummary"];
            balances: {
                evm?: {
                    native: string;
                    nativeFormatted: string;
                    chainId: number;
                    symbol: string;
                };
                solana?: {
                    native: string;
                    nativeFormatted: string;
                    chainId: number;
                    symbol: string;
                };
            };
            spend: {
                today: string;
                thisWeek: string;
                thisMonth: string;
                todayFormatted: string;
                thisWeekFormatted: string;
                thisMonthFormatted: string;
            };
            policies: unknown[];
            pendingApprovals: number;
            recentTransactions: unknown[];
        };
        AgentIdentitySummary: {
            id: string;
            tenantId: string;
            name: string;
            walletAddress: string;
        };
        ErrorResponse: {
            /** @enum {boolean} */
            ok: false;
            error: string;
        };
        TradeTokenStatus: {
            agentId: string;
            /** @enum {string} */
            status: "unknown" | "observed";
            exp: number | null;
            observedAt: number | null;
            expiresInSeconds: number | null;
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;
