import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getOpenApiSpec } from "../packages/api/src/openapi";

const runtimePath = resolve(import.meta.dir, "../docs/openapi.json");
const docsPath = resolve(import.meta.dir, "../docs/api-reference/openapi.json");
const runtimeDocument = getOpenApiSpec();
const docsDocument = {
  ...runtimeDocument,
  servers: [
    {
      url: "http://localhost:3200",
      description: "Your self-hosted Steward instance. Replace this URL with your deployment.",
    },
  ],
};

await Promise.all([
  writeFile(runtimePath, `${JSON.stringify(runtimeDocument, null, 2)}\n`, "utf8"),
  writeFile(docsPath, `${JSON.stringify(docsDocument, null, 2)}\n`, "utf8"),
]);
console.log(`Wrote ${runtimePath}`);
console.log(`Wrote ${docsPath}`);
