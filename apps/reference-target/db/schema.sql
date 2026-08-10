-- Reference-target Postgres schema with Row-Level Security (spec §5.2, §9).
-- This encodes the audit substrate: shared Postgres + RLS, tenant_id claim as
-- the discriminator. The in-memory store (src/store.ts) mirrors this for the
-- dependency-free CI path; this file documents the real, patched shape.

CREATE TABLE IF NOT EXISTS invoices (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  amount_cents  INTEGER NOT NULL,
  memo          TEXT NOT NULL
);

-- The application sets `SET LOCAL app.tenant_id = '<verified claim>'` per request.
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;

-- ✅ PATCHED policy: the USING clause partitions by the authenticated tenant.
-- The cross-tenant-read finding corresponds to this policy being ABSENT or the
-- USING clause being missing/mis-scoped.
CREATE POLICY invoices_tenant_isolation ON invoices
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- ❌ The vulnerable variant the tenant-isolation probe catches would be either:
--   1. No RLS enabled, or
--   2. A policy with `USING (true)`, or
--   3. Trusting a client-supplied tenant_id instead of the verified claim.
