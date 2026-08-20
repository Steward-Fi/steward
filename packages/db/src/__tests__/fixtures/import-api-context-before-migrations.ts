let unhandled: unknown;
process.on("unhandledRejection", (error) => {
  unhandled = error;
});

await import("../../../../api/src/services/context");
await Bun.sleep(250);
if (unhandled !== undefined) throw unhandled;
console.log("API_CONTEXT_IMPORT_NO_DATABASE_IO");
process.exit(0);
