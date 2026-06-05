import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getOpenApiSpec } from "../packages/api/src/openapi";

const outPath = resolve(import.meta.dir, "../docs/openapi.json");
const spec = JSON.stringify(getOpenApiSpec(), null, 2);

await writeFile(outPath, `${spec}\n`, "utf8");
console.log(`Wrote ${outPath}`);
