import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { type PGlite } from "@electric-sql/pglite";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(120_000);
let client: PGlite;

describe("SigV4 injection migration (0100)", () => {
  beforeAll(async () => {
    ({ client } = await createPGLiteDb("memory://"));
    await client.exec(`
      INSERT INTO tenants(id,name,api_key_hash) VALUES ('t204','T','h');
      INSERT INTO secrets(id,tenant_id,name,ciphertext,iv,auth_tag,salt,version)
        VALUES ('00000000-0000-4000-8000-000000000204','t204','aws','x','x','x','x',1);
    `);
  });

  afterAll(async () => client.close());

  test("persists only a service/region-bound EC2 strategy", async () => {
    await client.exec(`
      INSERT INTO secret_routes(
        id,tenant_id,secret_id,host_pattern,path_pattern,method,inject_as,inject_key,
        injection_strategy,injection_config
      ) VALUES (
        '00000000-0000-4000-8000-000000000205','t204',
        '00000000-0000-4000-8000-000000000204','ec2.us-west-2.amazonaws.com','/','POST',
        'header','authorization','sigv4','{"service":"ec2","region":"us-west-2"}'::jsonb
      );
    `);
    await expect(
      client.exec(`
        INSERT INTO secret_routes(
          tenant_id,secret_id,host_pattern,path_pattern,method,inject_as,inject_key,
          injection_strategy,injection_config
        ) VALUES (
          't204','00000000-0000-4000-8000-000000000204','attacker.amazonaws.com','/','POST',
          'header','authorization','sigv4','{"service":"ec2","region":"us-west-2"}'::jsonb
        );
      `),
    ).rejects.toThrow();
  });

  test("strategy/config changes stale approvals by bumping authority_revision", async () => {
    await client.exec(`
      UPDATE secret_routes SET
        host_pattern='ec2.eu-central-1.amazonaws.com',
        injection_config='{"service":"ec2","region":"eu-central-1"}'::jsonb
      WHERE id='00000000-0000-4000-8000-000000000205';
    `);
    const result = await client.query<{ authority_revision: number; host_pattern: string }>(`
      SELECT authority_revision,host_pattern FROM secret_routes
      WHERE id='00000000-0000-4000-8000-000000000205'
    `);
    expect(result.rows[0]).toEqual({
      authority_revision: 2,
      host_pattern: "ec2.eu-central-1.amazonaws.com",
    });
  });

  test("profile CHECK retains every prior profile and admits AWS only by exact name", async () => {
    const constraint = await client.query<{ def: string }>(`
      SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint
      WHERE conname='provider_action_bindings_profile_chk'
    `);
    expect(constraint.rows[0]?.def).toContain("aws.provider-action.v1");
    expect(constraint.rows[0]?.def).toContain("generic-http.provider-action.v1");
    expect(constraint.rows[0]?.def).toContain("github.provider-action.v1");
    expect(constraint.rows[0]?.def).toContain("x.provider-action.v1");
    expect(constraint.rows[0]?.def).toContain("slack.provider-action.v1");
    expect(constraint.rows[0]?.def).toContain("google.provider-action.v1");
  });
});
