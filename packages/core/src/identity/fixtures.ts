import type {
  FixtureView,
  GuardedHttpClient,
  IdentityRef,
  Logger,
  ScratchFixture,
  TargetModel,
} from "@perimeter/sdk";
import { scratchPath } from "@perimeter/sdk";

/**
 * Scratch fixture management (spec §4.3). When a probe needs "an object owned by
 * tenant B", the engine creates it via the sanctioned `creates:` endpoint as
 * tenant B, tracks its id, and tears it down at scan end — so cross-tenant
 * probes operate on disposable, known data instead of poking real records.
 *
 * Ids created here are the ONLY object ids a permitted write may target
 * (enforced by the SafetyGuard scratch-object rule).
 */

export interface ScratchObject {
  id: string;
  kind: string;
  ownerTenant: string;
  ownerIdentity: IdentityRef;
  /** How to delete it at teardown (endpoint id + resolved path), if one is modeled. */
  teardown?: { endpointId: string; path: string };
}

export interface FixtureManagerOptions {
  logger?: Logger;
  /**
   * The live set of scratch object ids the SafetyGuard consults for the write
   * allow-list. Share ONE instance between the setup guard and this manager so
   * that ids created after the guard was constructed are still recognized
   * (teardown writes, probe scratch writes). A fresh set is used if omitted.
   */
  ids?: Set<string>;
}

export class FixtureManager {
  readonly #target: TargetModel;
  readonly #http: GuardedHttpClient;
  readonly #logger: Logger | undefined;
  readonly #created: ScratchObject[] = [];
  readonly #ids: Set<string>;

  constructor(target: TargetModel, http: GuardedHttpClient, opts: FixtureManagerOptions = {}) {
    this.#target = target;
    this.#http = http;
    this.#logger = opts.logger;
    this.#ids = opts.ids ?? new Set<string>();
  }

  /** Pathnames of the `creates:` factory endpoints — feeds the setup guard allow-list. */
  static factoryPaths(target: TargetModel): Set<string> {
    return new Set(target.endpoints.filter((e) => e.creates).map((e) => e.path));
  }

  /** Live set of scratch object ids — feeds the SafetyGuard write allow-list. */
  scratchObjectIds(): Set<string> {
    return this.#ids;
  }

  /** A claimed scratch ID alone never authorizes a write to a different record. */
  permitsWrite(method: string, url: string, id: string): boolean {
    return this.#created.some((object) => object.id === id && this.#target.endpoints.some((endpoint) => {
      if (endpoint.graphql || endpoint.method !== method || endpoint.objectRef?.kind !== object.kind) return false;
      const path = scratchPath(endpoint, id);
      if (!path) return false;
      const expected = new URL(path, this.#target.baseUrl);
      return expected.pathname === path && expected.href === url;
    }));
  }

  /** Read-only view handed to probes via ProbeContext (spec §4.3). */
  view(): FixtureView {
    const created = this.#created;
    return {
      owned(kind: string, ownerIdentity: IdentityRef): ScratchFixture | undefined {
        return created.find((o) => o.kind === kind && o.ownerIdentity === ownerIdentity);
      },
      ofKind(kind: string): readonly ScratchFixture[] {
        return created.filter((o) => o.kind === kind);
      },
    };
  }

  /**
   * Create a scratch object of `kind` owned by `asIdentity`'s tenant, using the
   * modeled `creates:` factory endpoint. This is the engine's one sanctioned
   * write path (spec §4.3); the setup guard permits it because the operator
   * annotated the endpoint `creates:` and asserted authorization.
   */
  async create(kind: string, asIdentity: IdentityRef): Promise<ScratchObject> {
    const factory = this.#target.endpoints.find((e) => e.creates === kind);
    if (!factory) {
      throw new Error(`no endpoint declares creates: "${kind}" — cannot make scratch fixture`);
    }

    const res = await this.#http.request({
      method: factory.method,
      url: factory.path,
      as: asIdentity,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(factory.fixture?.body ?? {}),
    });
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`fixture factory "${factory.id}" returned ${res.status} creating a ${kind}`);
    }

    const id = await this.#extractId(res, kind, factory.fixture?.responseIdPath);
    const obj: ScratchObject = {
      id,
      kind,
      ownerTenant: this.#identityTenant(asIdentity),
      ownerIdentity: asIdentity,
    };
    const teardown = this.#teardownFor(kind, id);
    if (teardown) obj.teardown = teardown;
    this.#created.push(obj);
    this.#ids.add(id);
    this.#logger?.debug("scratch fixture created", { kind, id, owner: asIdentity });
    return obj;
  }

  /** Tear down every scratch object created this scan. Best-effort, logged. */
  async teardownAll(): Promise<void> {
    for (const obj of this.#created) {
      if (!obj.teardown) {
        this.#logger?.debug("no delete endpoint modeled; leaving scratch object", { id: obj.id });
        continue;
      }
      try {
        const response = await this.#http.request({
          method: "DELETE",
          url: obj.teardown.path,
          as: obj.ownerIdentity,
          targetsScratchObjectId: obj.id,
        });
        if (response.status < 200 || response.status >= 300) throw new Error(`cleanup returned ${response.status}`);
      } catch (err) {
        this.#logger?.warn("scratch teardown failed (ignored)", { id: obj.id, error: String(err) });
      }
    }
    this.#created.length = 0;
    this.#ids.clear();
  }

  /** Resolve a DELETE endpoint for `kind`, substituting the id, if one is modeled. */
  #teardownFor(kind: string, id: string): { endpointId: string; path: string } | undefined {
    const del = this.#target.endpoints.find(
      (e) => e.method === "DELETE" && e.objectRef?.kind === kind,
    );
    if (!del?.objectRef) return undefined;
    const path = scratchPath(del, id);
    if (!path) return undefined;
    return { endpointId: del.id, path };
  }

  async #extractId(
    res: { json<T = unknown>(): Promise<T>; headers: Record<string, string> },
    kind: string,
    responseIdPath?: string[],
  ): Promise<string> {
    if (responseIdPath) {
      let candidate: unknown;
      try {
        candidate = await res.json();
      } catch {
        throw new Error(`fixture.responseIdPath for "${kind}" requires a JSON response`);
      }
      for (const key of responseIdPath) {
        candidate = candidate !== null && typeof candidate === "object" && Object.hasOwn(candidate, key)
          ? (candidate as Record<string, unknown>)[key]
          : undefined;
      }
      if ((typeof candidate === "string" && candidate.trim().length > 0) ||
          (typeof candidate === "number" && Number.isFinite(candidate))) return String(candidate);
      // Never guess a different object when the operator supplied an exact mapping.
      throw new Error(`fixture.responseIdPath for "${kind}" did not resolve to a non-empty string or finite number`);
    }
    try {
      const body = (await res.json()) as Record<string, unknown>;
      const candidate =
        body.id ?? body[`${kind}Id`] ?? (body.data as Record<string, unknown> | undefined)?.id;
      if (typeof candidate === "string" || typeof candidate === "number") {
        return String(candidate);
      }
    } catch {
      // fall through to Location header
    }
    const loc = res.headers.location ?? res.headers.Location;
    if (loc) {
      const seg = loc.split("/").filter(Boolean).pop();
      if (seg) return seg;
    }
    throw new Error(`could not extract created ${kind} id from the factory response`);
  }

  #identityTenant(ref: IdentityRef): string {
    const spec = this.#target.identities.find((i) => i.ref === ref);
    if (!spec) throw new Error(`unknown identity "${ref}"`);
    return spec.tenant;
  }
}
