import type { Buffer } from "node:buffer";

export declare const KDF_SALT_MIN_BYTES: 16;
export declare function decodeKdfSalt(value: string, variableName?: string): Buffer;
