const warnings: string[] = [];
console.warn = (...values: unknown[]) => {
  warnings.push(values.map(String).join(" "));
};

const { WALLETCONNECT_PROJECT_ID } = await import("../wagmi");

process.stdout.write(
  JSON.stringify({
    projectId: WALLETCONNECT_PROJECT_ID,
    warnings,
    browserGlobalsPresent:
      "window" in globalThis || "indexedDB" in globalThis || "localStorage" in globalThis,
  }),
);

export {};
