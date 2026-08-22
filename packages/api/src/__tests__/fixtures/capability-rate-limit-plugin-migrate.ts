import { createDb, runPluginMigrations } from "@stwd/db";
import { capabilitiesPlugin } from "@stwd/plugin-capabilities";
import { migrate as postgresMigrate } from "drizzle-orm/postgres-js/migrator";

if (!capabilitiesPlugin.migrations) throw new Error("capability plugin migration is missing");
const database = createDb(process.env.DATABASE_URL!);
try {
  await runPluginMigrations(capabilitiesPlugin.migrations, {
    db: database.db,
    client: database.client,
    migrateFn: postgresMigrate as never,
  });
} finally {
  await database.client.end();
}
