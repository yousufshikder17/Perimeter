import { createHash } from "node:crypto";
import { appendFile } from "node:fs/promises";
import type { HttpExchange } from "@perimeter/sdk";

/**
 * Append-only, content-addressed audit log (spec §4.1 responsibility 4).
 *
 * Every request/response is written as one NDJSON line, tagged with the probe,
 * identity, and tenant it was issued under, and stamped with a content address.
 * The log IS the reproduction artifact and the compliance trail. Interrupted
 * scans resume from it (spec §4.1 responsibility 5).
 *
 * Secrets are already redacted upstream (see redaction.ts) before entries reach
 * here. Evidence never leaves the operator's machine.
 */

export interface AuditEntry {
  /** Content address of this entry — the id evidence bundles reference. */
  ref: string;
  seq: number;
  timestamp: string;
  scanId: string;
  probeId: string;
  identityRef?: string;
  tenant?: string;
  exchange: HttpExchange;
}

export interface AuditSink {
  append(entry: Omit<AuditEntry, "ref" | "seq" | "timestamp">): Promise<AuditEntry>;
  /** Content-addressed pointers appended so far (for evidence.auditRefs). */
  refs(): string[];
}

function contentAddress(payload: unknown): string {
  return "sha256:" + createHash("sha256").update(JSON.stringify(payload)).digest("hex").slice(0, 24);
}

/** NDJSON-file-backed sink used in local/CI profiles. */
export class NdjsonAuditLog implements AuditSink {
  readonly #path: string;
  #seq = 0;
  readonly #refs: string[] = [];

  constructor(path: string) {
    this.#path = path;
  }

  async append(
    entry: Omit<AuditEntry, "ref" | "seq" | "timestamp">,
  ): Promise<AuditEntry> {
    const full: AuditEntry = {
      ...entry,
      seq: this.#seq++,
      timestamp: new Date().toISOString(),
      ref: contentAddress(entry.exchange),
    };
    this.#refs.push(full.ref);
    await appendFile(this.#path, JSON.stringify(full) + "\n", "utf8");
    return full;
  }

  refs(): string[] {
    return [...this.#refs];
  }
}

/** In-memory sink for tests and the fixture harness. */
export class MemoryAuditLog implements AuditSink {
  readonly entries: AuditEntry[] = [];
  #seq = 0;

  async append(
    entry: Omit<AuditEntry, "ref" | "seq" | "timestamp">,
  ): Promise<AuditEntry> {
    const full: AuditEntry = {
      ...entry,
      seq: this.#seq++,
      timestamp: new Date().toISOString(),
      ref: contentAddress(entry.exchange),
    };
    this.entries.push(full);
    return full;
  }

  refs(): string[] {
    return this.entries.map((e) => e.ref);
  }
}
