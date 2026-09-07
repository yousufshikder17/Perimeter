import { request as undiciRequest } from "undici";
import type {
  GuardedHttpClient,
  GuardedRequest,
  GuardedResponse,
  HttpExchange,
  Identity,
  IdentityRef,
  SafetyClass,
} from "@perimeter/sdk";
import { SafetyGuard } from "../safety/guard.js";
import { RateLimiter } from "../safety/rate-limiter.js";
import { MutableBudget } from "../runtime/budget.js";
import type { AuditSink } from "../audit/audit-log.js";
import { MAX_CAPTURED_BODY_BYTES, redactBody, redactHeaders } from "../audit/redaction.js";

/**
 * The ONE network egress (spec §3.2 rule 1, §4.2). Probes never see raw `fetch`
 * or `node:http`; they get this. Every call, in order:
 *   1. consumes the per-probe budget,
 *   2. passes the safety guard (host allow-list, method + payload policy),
 *   3. waits on the global + per-host rate limiter,
 *   4. is issued via undici,
 *   5. is recorded — redacted — to the append-only audit log.
 *
 * There is deliberately no way to skip a step. A probe holding this object
 * cannot reach the network any other way.
 */
export interface GuardedHttpClientDeps {
  /** Authentication exchanges must never persist credential-bearing bodies. */
  captureBodies?: boolean;
  /** Optional hard response-body limit for bounded discovery. */
  maxResponseBytes?: number;
  baseUrl: string;
  probeId: string;
  probeSafetyClass: SafetyClass;
  guard: SafetyGuard;
  limiter: RateLimiter;
  budget: MutableBudget;
  audit: AuditSink;
  scanId: string;
  resolveIdentity: (ref: IdentityRef) => Identity;
  signal: AbortSignal;
}

let exchangeCounter = 0;

export class GuardedHttpClientImpl implements GuardedHttpClient {
  readonly #d: GuardedHttpClientDeps;

  constructor(deps: GuardedHttpClientDeps) {
    if (deps.maxResponseBytes !== undefined && (!Number.isSafeInteger(deps.maxResponseBytes) || deps.maxResponseBytes <= 0)) {
      throw new Error("maxResponseBytes must be a positive safe integer");
    }
    this.#d = deps;
  }

  get(
    url: string,
    init: Omit<GuardedRequest, "method" | "url"> = {},
  ): Promise<GuardedResponse> {
    return this.request({ method: "GET", url, ...init });
  }

  async request(req: GuardedRequest): Promise<GuardedResponse> {
    this.#d.signal.throwIfAborted();

    const url = this.#resolveUrl(req.url);
    const bodyText = typeof req.body === "string" ? req.body : req.body ? Buffer.from(req.body).toString("utf8") : undefined;

    // (1) budget — throws when exhausted
    this.#d.budget.consume();

    // (2) safety guard — throws SafetyViolation on any policy breach
    this.#d.guard.check({
      method: req.method,
      url,
      probeSafetyClass: this.#d.probeSafetyClass,
      payloadParts: [new URL(url).search, bodyText],
      ...(req.targetsScratchObjectId ? { targetsScratchObjectId: req.targetsScratchObjectId } : {}),
    });

    // (3) rate limiter
    const host = new URL(url).host;
    await this.#d.limiter.acquire(host, this.#d.signal);

    // credentials from the engine-owned identity, if requested
    const authHeaders = req.as ? await this.#d.resolveIdentity(req.as).headers() : {};
    const outHeaders = { ...(req.headers ?? {}), ...authHeaders };

    // (4) issue
    const startedAt = Date.now();
    const res = await undiciRequest(url, {
      method: req.method,
      headers: outHeaders,
      ...(req.body !== undefined ? { body: req.body } : {}),
      signal: this.#d.signal,
    });
    let respText: string;
    if (this.#d.maxResponseBytes === undefined) {
      respText = await res.body.text();
    } else {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of res.body) {
        size += chunk.length;
        if (size > this.#d.maxResponseBytes) {
          res.body.destroy();
          await this.#d.audit.append({
            scanId: this.#d.scanId, probeId: this.#d.probeId,
            ...(req.as ? { identityRef: req.as, tenant: this.#d.resolveIdentity(req.as).tenant } : {}),
            exchange: this.#buildExchange(req, url, outHeaders, bodyText, res, "Response body limit exceeded", Date.now() - startedAt),
          });
          throw new Error("Response body limit exceeded");
        }
        chunks.push(Buffer.from(chunk));
      }
      respText = Buffer.concat(chunks).toString("utf8");
    }
    const elapsedMs = Date.now() - startedAt;

    // (5) record — redacted — to the audit log
    const exchange = this.#buildExchange(req, url, outHeaders, bodyText, res, respText, elapsedMs);
    const entry = await this.#d.audit.append({
      scanId: this.#d.scanId,
      probeId: this.#d.probeId,
      ...(req.as ? { identityRef: req.as, tenant: this.#d.resolveIdentity(req.as).tenant } : {}),
      exchange,
    });
    // stamp the audit ref back onto the exchange so evidence can point to it
    (exchange as { ref: string }).ref = entry.ref;

    return this.#buildResponse(res.statusCode, res.headers, respText, elapsedMs, exchange);
  }

  #resolveUrl(url: string): string {
    return /^https?:\/\//i.test(url) ? url : new URL(url, this.#d.baseUrl).toString();
  }

  #buildExchange(
    req: GuardedRequest,
    url: string,
    reqHeaders: Record<string, string>,
    bodyText: string | undefined,
    res: { statusCode: number; headers: Record<string, string | string[] | undefined> },
    respText: string,
    elapsedMs: number,
  ): HttpExchange {
    return {
      ref: `exch-${exchangeCounter++}`,
      request: {
        method: req.method,
        url,
        headers: redactHeaders(reqHeaders),
        ...(bodyText !== undefined ? { body: this.#d.captureBodies === false ? "«redacted»" : redactBody(bodyText)! } : {}),
      },
      response: {
        status: res.statusCode,
        headers: redactHeaders(flattenHeaders(res.headers)),
        body: this.#d.captureBodies === false ? "«redacted»" : redactBody(respText.slice(0, MAX_CAPTURED_BODY_BYTES)),
        elapsedMs,
      },
      ...(req.as ? { issuedAs: req.as } : {}),
    };
  }

  #buildResponse(
    status: number,
    headers: Record<string, string | string[] | undefined>,
    text: string,
    elapsedMs: number,
    exchange: HttpExchange,
  ): GuardedResponse {
    return {
      status,
      setCookies: typeof headers["set-cookie"] === "string" ? [headers["set-cookie"]] : headers["set-cookie"] ?? [],
      headers: flattenHeaders(headers),
      elapsedMs,
      exchange,
      async text() {
        return text;
      },
      async json<T = unknown>() {
        return JSON.parse(text) as T;
      },
    };
  }
}

function flattenHeaders(
  h: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue;
    out[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}
