-- the example plugin's OWN schema. applied by the host into a per-plugin
-- namespaced bookkeeping table (drizzle.__drizzle_migrations_plugin_example),
-- never into the core's drizzle.__drizzle_migrations journal.
CREATE TABLE "example_log" (
	"id" serial PRIMARY KEY NOT NULL,
	"note" text NOT NULL,
	"created_at" timestamptz DEFAULT now() NOT NULL
);
