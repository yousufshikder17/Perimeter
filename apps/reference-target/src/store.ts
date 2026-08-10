/**
 * In-memory data store for the reference target. Mirrors the audit substrate:
 * shared store, tenant_id discriminator (the analog of shared Postgres + RLS).
 *
 * Vulnerabilities are toggled by env so the SAME app serves as both the
 * "vulnerable" and "patched" fixture (spec §3.4). See db/schema.sql for the
 * corresponding real Postgres RLS policies.
 */

export interface Invoice {
  id: string;
  tenantId: string;
  ownerUserId: string;
  amountCents: number;
  memo: string;
}

export interface Vulnerabilities {
  /** If true, reads ignore the tenant discriminator (missing RLS USING clause). */
  crossTenantRead: boolean;
  /** If true, object reads skip the ownership check (IDOR). */
  idor: boolean;
  /** If true, protected routes are served without auth. */
  missingAuth: boolean;
  /** If true, login/OTP endpoints are NOT rate-limited. */
  noRateLimit: boolean;
}

export function vulnsFromEnv(): Vulnerabilities {
  const on = (k: string) => process.env[k] === "1" || process.env[k] === "true";
  // Default: vulnerable (this is a test target). Set PERIMETER_PATCHED=1 to patch all.
  const patched = on("PERIMETER_PATCHED");
  return {
    crossTenantRead: !patched && !on("FIX_CROSS_TENANT"),
    idor: !patched && !on("FIX_IDOR"),
    missingAuth: !patched && on("BREAK_AUTH"),
    noRateLimit: !patched && !on("FIX_RATE_LIMIT"),
  };
}

const SEED: Invoice[] = [
  { id: "inv-a-1", tenantId: "tenant-a", ownerUserId: "user-a", amountCents: 1000, memo: "tenant A invoice" },
  { id: "inv-b-1", tenantId: "tenant-b", ownerUserId: "user-b", amountCents: 9999, memo: "tenant B invoice" },
];

export class Store {
  readonly #invoices = new Map<string, Invoice>(SEED.map((i) => [i.id, i]));

  create(inv: Omit<Invoice, "id">): Invoice {
    const id = `inv-${inv.tenantId}-${this.#invoices.size + 1}`;
    const full = { ...inv, id };
    this.#invoices.set(id, full);
    return full;
  }

  /** Read respecting (or not respecting) the tenant boundary, per vuln flags. */
  getInvoice(id: string, callerTenant: string, vulns: Vulnerabilities): Invoice | null {
    const inv = this.#invoices.get(id);
    if (!inv) return null;
    if (vulns.crossTenantRead) return inv; // BUG: no tenant filter
    return inv.tenantId === callerTenant ? inv : null; // patched: RLS-equivalent filter
  }
}
