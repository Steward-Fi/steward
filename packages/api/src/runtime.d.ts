declare const process: {
  env: Record<string, string | undefined>;
  exit(code?: number): never;
  on(signal: "SIGINT" | "SIGTERM", listener: () => void): void;
};

declare const Bun: {
  serve(options: {
    port: number;
    fetch(
      request: Request,
      server: { requestIP(request: Request): { address: string } | null },
    ): Response | Promise<Response>;
    idleTimeout?: number;
  }): {
    port: number;
    stop(closeActiveConnections?: boolean): void;
  };
};

declare module "crypto" {
  export interface CipherGCM {
    update(data: string, inputEncoding: "utf8", outputEncoding: "hex"): string;
    final(outputEncoding: "hex"): string;
    getAuthTag(): Buffer;
  }

  export interface DecipherGCM {
    setAuthTag(buffer: Buffer): void;
    update(data: string, inputEncoding: "hex", outputEncoding: "utf8"): string;
    final(outputEncoding: "utf8"): string;
  }

  export function randomBytes(size: number): Buffer;
  export function scryptSync(
    password: string | Buffer,
    salt: string | Buffer,
    keylen: number,
  ): Buffer;
  export function createCipheriv(algorithm: string, key: Buffer, iv: Buffer): CipherGCM;
  export function createDecipheriv(algorithm: string, key: Buffer, iv: Buffer): DecipherGCM;
}

declare class Buffer extends Uint8Array {
  static from(
    data: string | Uint8Array | ArrayBuffer | readonly number[],
    encoding?: "utf8" | "hex" | "base64" | "base64url",
  ): Buffer;
  static alloc(size: number): Buffer;
  static concat(list: readonly Uint8Array[]): Buffer;
  toString(encoding?: "utf8" | "hex" | "base64" | "base64url"): string;
}
