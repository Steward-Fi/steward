/**
 * GENERATED FILE — do not edit by hand.
 * Produced by packages/api/scripts/generate-sdk-types.ts from the OpenAPI
 * document (packages/api/openapi.json). Run `bun run openapi:generate` in
 * @stwd/api to regenerate after a route schema changes.
 */

export interface paths {
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
        TradeTokenStatus: {
            agentId: string;
            /** @enum {string} */
            status: "unknown" | "observed";
            exp: number | null;
            observedAt: number | null;
            expiresInSeconds: number | null;
        };
        ErrorResponse: {
            /** @enum {boolean} */
            ok: false;
            error: string;
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
