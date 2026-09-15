import { randomUUID } from "node:crypto";
import pg from "pg";
import type { Invoice } from "./store.js";

const columns =
  'id, tenant_id AS "tenantId", owner_user_id AS "ownerUserId", amount_cents AS "amountCents", memo';

/** Real RLS: no tenant WHERE clause. Connect as a non-owner application role. */
export class PostgresStore {
  readonly pool: pg.Pool;

  constructor(connectionString: string) {
    this.pool = new pg.Pool({
      connectionString,
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
      idle_in_transaction_session_timeout: 5000,
    });
    this.pool.on("error", () => {});
  }

  async withTenant<T>(
    tenant: string | undefined,
    fn: (client: pg.PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await this.pool.connect();
    let failed = false;
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenant ?? ""]);
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch {
      failed = true;
      await client.query("ROLLBACK").catch(() => {});
      throw new Error("Reference PostgreSQL operation failed");
    } finally {
      client.release(failed);
    }
  }

  create(inv: Omit<Invoice, "id">): Promise<Invoice> {
    return this.withTenant(inv.tenantId, async (client) => {
      const result = await client.query<Invoice>(
        "INSERT INTO public.invoices (id,tenant_id,owner_user_id,amount_cents,memo) VALUES ($1,$2,$3,$4,$5) RETURNING " +
          columns,
        [randomUUID(), inv.tenantId, inv.ownerUserId, inv.amountCents, inv.memo],
      );
      return result.rows[0]!;
    });
  }

  getInvoice(id: string, tenant: string): Promise<Invoice | null> {
    return this.withTenant(
      tenant,
      async (client) =>
        (
          await client.query<Invoice>("SELECT " + columns + " FROM public.invoices WHERE id=$1", [
            id,
          ])
        ).rows[0] ?? null,
    );
  }

  close(): Promise<void> {
    return this.pool.end();
  }
}
