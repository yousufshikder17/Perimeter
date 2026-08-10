import type {
  FixtureView,
  Probe,
  ProbeContext,
  GuardedHttpClient,
  GuardedRequest,
  GuardedResponse,
  HttpExchange,
  Identity,
  IdentityRef,
  Report,
  ScratchFixture,
  TargetModel,
} from "@perimeter/sdk";
import { isSkip } from "@perimeter/sdk";
import { DeterministicRng } from "../runtime/rng.js";
import { VirtualClock } from "../runtime/clock.js";
import { ConsoleLogger } from "../runtime/logger.js";
import { MutableBudget } from "../runtime/budget.js";

/**
 * Probe test harness (spec §3.4). A recorded-target fixture mode: a probe runs
 * against canned request→response pairs so contributors prove both the
 * true-positive (vulnerable fixture) and true-negative (patched fixture) without
 * a live target. Every standard-library probe ships with both fixtures.
 */

export interface RecordedExchange {
  /** Match on method + a URL substring (path/query). First match wins. */
  match: { method: string; urlIncludes: string; as?: IdentityRef };
  respond: { status: number; headers?: Record<string, string>; body?: string };
}

export interface HarnessOptions {
  target: TargetModel;
  fixtures: RecordedExchange[];
  /** Scratch objects the engine would have provisioned (spec §4.3), exposed to the probe via ctx.fixtures. */
  scratchObjects?: ScratchFixture[];
  seed?: string;
}

export interface HarnessResult {
  reports: Report[];
  requests: GuardedRequest[];
  skipped: string | null;
}

/** Run a probe against recorded fixtures; collect its reports and its requests. */
export async function runProbeAgainstFixtures(
  probe: Probe,
  opts: HarnessOptions,
): Promise<HarnessResult> {
  const reports: Report[] = [];
  const requests: GuardedRequest[] = [];
  const seed = opts.seed ?? "test-seed";

  const http = new RecordedHttpClient(opts.fixtures, requests);
  const ctx: ProbeContext = {
    target: opts.target,
    http,
    fixtures: fixtureView(opts.scratchObjects ?? []),
    budget: new MutableBudget(probe.manifest.safety.maxRequests),
    logger: new ConsoleLogger("warn"),
    rng: new DeterministicRng(`${seed}::${probe.manifest.id}`),
    clock: new VirtualClock(),
    signal: new AbortController().signal,
    identity: (ref) => fakeIdentity(ref, opts.target),
    report: (r) => reports.push(r),
  };

  const plan = await probe.plan(ctx);
  if (isSkip(plan)) return { reports, requests, skipped: plan.reason };
  await probe.run(plan, ctx);
  return { reports, requests, skipped: null };
}

class RecordedHttpClient implements GuardedHttpClient {
  #counter = 0;
  constructor(
    private readonly fixtures: RecordedExchange[],
    private readonly recorded: GuardedRequest[],
  ) {}

  get(url: string, init: Omit<GuardedRequest, "method" | "url"> = {}): Promise<GuardedResponse> {
    return this.request({ method: "GET", url, ...init });
  }

  async request(req: GuardedRequest): Promise<GuardedResponse> {
    this.recorded.push(req);
    const fx = this.fixtures.find(
      (f) =>
        f.match.method.toUpperCase() === req.method.toUpperCase() &&
        req.url.includes(f.match.urlIncludes) &&
        (f.match.as === undefined || f.match.as === req.as),
    );
    if (!fx) throw new Error(`no recorded fixture for ${req.method} ${req.url}`);

    const body = fx.respond.body ?? "";
    const exchange: HttpExchange = {
      ref: `fixture-exch-${this.#counter++}`,
      request: { method: req.method, url: req.url, headers: req.headers ?? {} },
      response: { status: fx.respond.status, headers: fx.respond.headers ?? {}, body, elapsedMs: 1 },
      ...(req.as ? { issuedAs: req.as } : {}),
    };
    return {
      status: fx.respond.status,
      headers: fx.respond.headers ?? {},
      elapsedMs: 1,
      exchange,
      async text() {
        return body;
      },
      async json<T = unknown>() {
        return JSON.parse(body) as T;
      },
    };
  }
}

function fixtureView(objects: ScratchFixture[]): FixtureView {
  return {
    owned(kind, ownerIdentity) {
      return objects.find((o) => o.kind === kind && o.ownerIdentity === ownerIdentity);
    },
    ofKind(kind) {
      return objects.filter((o) => o.kind === kind);
    },
  };
}

function fakeIdentity(ref: IdentityRef, target: TargetModel): Identity {
  const spec = target.identities.find((i) => i.ref === ref);
  return {
    ref,
    tenant: spec?.tenant ?? "unknown",
    role: spec?.role ?? "member",
    async headers() {
      return { authorization: `Bearer test-${ref}` };
    },
  };
}
