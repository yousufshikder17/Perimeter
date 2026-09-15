-- Reference-target Postgres schema with Row-Level Security (spec §5.2, §9).
-- This encodes the audit substrate: shared Postgres + RLS, tenant_id claim as
-- the discriminator. The in-memory store (src/store.ts) mirrors this for the
-- dependency-free CI path; this file documents the real, patched shape.

-- Run ONLY in a new disposable database. Runtime must use this non-owner role.
CREATE ROLE perimeter_reference LOGIN NOSUPERUSER NOBYPASSRLS;
CREATE TABLE invoices (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  amount_cents  INTEGER NOT NULL,
  memo          TEXT NOT NULL
);

-- The application sets `SET LOCAL app.tenant_id = '<verified claim>'` per request.
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;

-- ✅ PATCHED policy: the USING clause partitions by the authenticated tenant.
-- An absent policy with RLS enabled is default-deny. Leaks require disabled RLS,
-- bypass privileges, or a permissive/mis-scoped USING clause.
CREATE POLICY invoices_tenant_isolation ON invoices
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''));

GRANT USAGE ON SCHEMA public TO perimeter_reference;
GRANT SELECT, INSERT, DELETE ON invoices TO perimeter_reference;
INSERT INTO invoices VALUES
  ('inv-a-1', 'tenant-a', 'user-a', 1000, 'tenant A invoice'),
  ('inv-b-1', 'tenant-b', 'user-b', 9999, 'tenant B invoice');
-- Assign a password using psql's \password perimeter_reference.
-- Controlled broken read policy (disposable database ONLY):
-- ALTER POLICY invoices_tenant_isolation ON invoices USING (true);

-- ❌ The vulnerable variant the tenant-isolation probe catches would be either:
--   1. No RLS enabled, or
--   2. A policy with `USING (true)`, or
--   3. Trusting a client-supplied tenant_id instead of the verified claim.
