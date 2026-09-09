import { createHash, randomUUID } from "node:crypto";
import { open, readFile, rename, unlink } from "node:fs/promises";
import { z } from "zod";
import { FindingSchema, PassSchema, type FindingRegistry } from "@perimeter/sdk";

const CompletedSchema = z.object({
  probeId: z.string(), findings: z.array(FindingSchema), passes: z.array(PassSchema),
  skipped: z.array(z.object({ probeId: z.string(), reason: z.string() }).strict()),
}).strict();
const StateSchema = z.object({
  version: z.literal(1), key: z.string(), scanId: z.string(), seed: z.string(), startedAt: z.string(),
  used: z.number().int().nonnegative(), completed: z.array(CompletedSchema),
}).strict();
type State = z.infer<typeof StateSchema>;

export class CheckpointError extends Error {}

/** One operator-owned file, locked per attempt; no credentials or target payloads stored. */
export class ScanCheckpoint {
  #pending = Promise.resolve();
  private constructor(readonly path: string, readonly state: State, readonly release: () => Promise<void>) {}

  static async open(path: string, resume: boolean, contract: unknown,
    meta: Pick<State, "scanId" | "seed" | "startedAt">): Promise<ScanCheckpoint> {
    const key = createHash("sha256").update(JSON.stringify(contract)).digest("hex");
    const lock = await open(`${path}.lock`, "wx", 0o600).catch(() => {
      throw new CheckpointError("Checkpoint is locked or its directory is unavailable; do not remove a lock while a scan is running");
    });
    const release = async () => { await lock.close(); await unlink(`${path}.lock`); };
    try {
      let state: State;
      if (resume) {
        state = StateSchema.parse(JSON.parse(await readFile(path, "utf8")));
        if (state.key !== key) throw new Error("contract mismatch");
        const ids = new Set<string>();
        for (const result of state.completed) {
          if (ids.has(result.probeId) || [...result.findings, ...result.passes, ...result.skipped]
            .some((report) => report.probeId !== result.probeId)) throw new Error("invalid completion");
          ids.add(result.probeId);
        }
      } else {
        // Exclusive creation refuses to overwrite earlier evidence.
        const file = await open(path, "wx", 0o600);
        state = { version: 1, key, ...meta, used: 0, completed: [] };
        try { await file.writeFile(JSON.stringify(state)); await file.sync(); } finally { await file.close(); }
      }
      return new ScanCheckpoint(path, state, release);
    } catch {
      await release();
      throw new CheckpointError("Cannot open checkpoint: missing, existing, malformed, or incompatible with this scan");
    }
  }

  reserve(used: number): Promise<void> {
    return this.#save(() => { this.state.used = Math.max(this.state.used, used); });
  }

  complete(probeId: string, registry: FindingRegistry): Promise<void> {
    const result = CompletedSchema.parse({ probeId,
      findings: registry.findings.filter((r) => r.probeId === probeId),
      passes: registry.passes.filter((r) => r.probeId === probeId),
      skipped: registry.skipped.filter((r) => r.probeId === probeId),
    });
    return this.#save(() => { this.state.completed.push(result); });
  }

  #save(update: () => void): Promise<void> {
    this.#pending = this.#pending.then(async () => {
      update();
      const temporary = `${this.path}.${randomUUID()}.tmp`;
      try {
        const file = await open(temporary, "wx", 0o600);
        try { await file.writeFile(JSON.stringify(this.state)); await file.sync(); } finally { await file.close(); }
        await rename(temporary, this.path);
      } catch {
        throw new CheckpointError("Checkpoint write failed; scan stopped before further traffic");
      } finally {
        await unlink(temporary).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
      }
    });
    return this.#pending;
  }
}
