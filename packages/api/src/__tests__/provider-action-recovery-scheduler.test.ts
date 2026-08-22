import { expect, test } from "bun:test";
import { recoverProviderActionTenant } from "../services/provider-reservation-reconciliation-scheduler";

test("tenant recovery reconciles reservations once even when required-audit delivery fails", async () => {
  let auditCalls = 0;
  let reservationCalls = 0;
  const result = await recoverProviderActionTenant("tenant-1", {
    async recoverRequiredAuditOutbox() {
      auditCalls += 1;
      throw new Error("signer unavailable");
    },
    async reconcilePolicyReservations() {
      reservationCalls += 1;
      return 2;
    },
  });

  expect(auditCalls).toBe(1);
  expect(reservationCalls).toBe(1);
  expect(result.auditsDelivered).toBe(0);
  expect(result.reservationsReconciled).toBe(2);
  expect(result.failures).toHaveLength(1);
  expect(result.failures[0]).toMatchObject({ tenantId: "tenant-1", domain: "required-audit" });
});

test("tenant recovery retains delivered-audit progress when reservation reconciliation fails", async () => {
  let auditCalls = 0;
  let reservationCalls = 0;
  const result = await recoverProviderActionTenant("tenant-2", {
    async recoverRequiredAuditOutbox() {
      auditCalls += 1;
      return 3;
    },
    async reconcilePolicyReservations() {
      reservationCalls += 1;
      throw new Error("redis unavailable");
    },
  });

  expect(auditCalls).toBe(1);
  expect(reservationCalls).toBe(1);
  expect(result.auditsDelivered).toBe(3);
  expect(result.reservationsReconciled).toBe(0);
  expect(result.failures).toHaveLength(1);
  expect(result.failures[0]).toMatchObject({ tenantId: "tenant-2", domain: "reservation" });
});
