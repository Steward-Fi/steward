import { describe, expect, it } from "bun:test";
import {
  isSigningCurve,
  isSigningCurveSupported,
  RAW_SIGNING_CHAIN_SUPPORT,
  rawSigningChainSupport,
  SIGNING_CURVE_SUPPORT,
  STARK_UNSUPPORTED_REASON,
  SUPPORTED_SIGNING_CURVES,
  signingCurveSupport,
} from "../index";

describe("signing-curve capability registry", () => {
  it("supports secp256k1 and ed25519 but not stark", () => {
    expect(SIGNING_CURVE_SUPPORT.secp256k1.supported).toBe(true);
    expect(SIGNING_CURVE_SUPPORT.ed25519.supported).toBe(true);
    expect(SIGNING_CURVE_SUPPORT.stark.supported).toBe(false);
  });

  it("gives stark a precise, honest unsupported reason (fail-closed, no hand-rolled crypto)", () => {
    expect(SIGNING_CURVE_SUPPORT.stark.unsupportedReason).toBe(STARK_UNSUPPORTED_REASON);
    expect(STARK_UNSUPPORTED_REASON).toContain("starknet");
  });

  it("SUPPORTED_SIGNING_CURVES lists exactly the signable curves", () => {
    expect([...SUPPORTED_SIGNING_CURVES].sort()).toEqual(["ed25519", "secp256k1"]);
    expect(SUPPORTED_SIGNING_CURVES).not.toContain("stark");
  });

  it("maps representative chains to the correct curve (raw-digest coverage)", () => {
    // secp256k1 covers EVM + Bitcoin-lineage + Tron.
    expect(SIGNING_CURVE_SUPPORT.secp256k1.exampleChains).toContain("ethereum");
    expect(SIGNING_CURVE_SUPPORT.secp256k1.exampleChains).toContain("bitcoin");
    expect(SIGNING_CURVE_SUPPORT.secp256k1.exampleChains).toContain("tron");
    expect(SIGNING_CURVE_SUPPORT.secp256k1.exampleChains).toContain("cosmos");
    // ed25519 covers Solana + Sui + Aptos + Stellar + Near.
    expect(SIGNING_CURVE_SUPPORT.ed25519.exampleChains).toContain("solana");
    expect(SIGNING_CURVE_SUPPORT.ed25519.exampleChains).toContain("sui");
    expect(SIGNING_CURVE_SUPPORT.ed25519.exampleChains).toContain("aptos");
    expect(SIGNING_CURVE_SUPPORT.ed25519.exampleChains).toContain("movement");
    expect(SIGNING_CURVE_SUPPORT.ed25519.exampleChains).toContain("ton");
  });

  it("maps Privy-parity non-EVM chains to raw-digest signing curves", () => {
    for (const chain of ["bitcoin", "spark", "lightning", "tron", "tempo", "cosmos"] as const) {
      expect(rawSigningChainSupport(chain)).toEqual({
        chain,
        curve: "secp256k1",
        supported: true,
        capability: "raw-digest",
      });
    }
    for (const chain of ["ton", "stellar", "near", "sui", "aptos", "movement"] as const) {
      expect(rawSigningChainSupport(chain)).toEqual({
        chain,
        curve: "ed25519",
        supported: true,
        capability: "raw-digest",
      });
    }
  });

  it("keeps Starknet visible but fail-closed until a vetted curve implementation exists", () => {
    expect(RAW_SIGNING_CHAIN_SUPPORT.starknet).toEqual({
      chain: "starknet",
      curve: "stark",
      supported: false,
      unsupportedReason: STARK_UNSUPPORTED_REASON,
      capability: "raw-digest",
    });
    expect(rawSigningChainSupport("starknet")?.supported).toBe(false);
  });

  it("rawSigningChainSupport returns undefined for unknown chains", () => {
    expect(rawSigningChainSupport("dogecoin")).toBeUndefined();
    expect(rawSigningChainSupport(undefined)).toBeUndefined();
  });

  it("isSigningCurve recognises known curves and rejects junk", () => {
    expect(isSigningCurve("secp256k1")).toBe(true);
    expect(isSigningCurve("ed25519")).toBe(true);
    expect(isSigningCurve("stark")).toBe(true);
    expect(isSigningCurve("p256")).toBe(false);
    expect(isSigningCurve(42)).toBe(false);
    expect(isSigningCurve(undefined)).toBe(false);
  });

  it("isSigningCurveSupported is true only for signable curves (stark is false)", () => {
    expect(isSigningCurveSupported("secp256k1")).toBe(true);
    expect(isSigningCurveSupported("ed25519")).toBe(true);
    expect(isSigningCurveSupported("stark")).toBe(false);
    expect(isSigningCurveSupported("nonsense")).toBe(false);
  });

  it("signingCurveSupport returns the record or undefined for unknown curves", () => {
    expect(signingCurveSupport("ed25519")?.curve).toBe("ed25519");
    expect(signingCurveSupport("stark")?.supported).toBe(false);
    expect(signingCurveSupport("bogus")).toBeUndefined();
  });
});
