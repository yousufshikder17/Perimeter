import type { Identity, IdentityRef, TargetModel, AuthScheme } from "@perimeter/sdk";
import { validateHeaderValue } from "node:http";

/**
 * Identity minting (spec §4.3). The engine owns this so probes stay declarative:
 * given the Target Model's auth recipe it produces ready-to-use `Identity`
 * handles per tenant/role, cached and refreshed on expiry.
 *
 * Credentials are resolved from env refs (never inline, spec §5.1). A `custom`
 * scheme delegates to a user-supplied hook.
 */

export type CustomAuthHook = (spec: {
  ref: IdentityRef;
  tenant: string;
  role: string;
  /** Forward to asynchronous credential work so scan cancellation can stop it. */
  signal?: AbortSignal;
}) => Promise<Record<string, string>>;

interface CachedCredential {
  headers: Promise<Record<string, string>>;
  expiresAtMs: number;
}

export class AuthenticationError extends Error {}

export class IdentityManager {
  readonly #target: TargetModel;
  readonly #customHook: CustomAuthHook | undefined;
  readonly #cache = new Map<IdentityRef, Identity>();
  readonly #credentials = new Map<IdentityRef, CachedCredential>();
  readonly #signal: AbortSignal | undefined;

  constructor(target: TargetModel, customHook?: CustomAuthHook, signal?: AbortSignal) {
    this.#target = target;
    this.#customHook = customHook;
    this.#signal = signal;
  }

  get(ref: IdentityRef): Identity {
    const cached = this.#cache.get(ref);
    if (cached) return cached;

    const spec = this.#target.identities.find((i) => i.ref === ref);
    if (!spec) throw new Error(`unknown identity ref "${ref}" (not in Target Model)`);

    const identity: Identity = {
      ref,
      tenant: spec.tenant,
      role: spec.role,
      headers: async () =>
        this.#mint(this.#target.auth.scheme, spec.ref, spec.tenant, spec.role, spec.credentials?.env),
    };

    this.#cache.set(ref, identity);
    return identity;
  }

  async #mint(
    scheme: AuthScheme,
    ref: IdentityRef,
    tenant: string,
    role: string,
    credentialEnv: string | undefined,
  ): Promise<Record<string, string>> {
    if (scheme === "custom") {
      this.#signal?.throwIfAborted();
      let cached = this.#credentials.get(ref);
      if (!cached || cached.expiresAtMs <= Date.now()) {
        const entry: CachedCredential = {
          expiresAtMs: Infinity, // Concurrent callers share the in-flight mint.
          headers: this.#invokeHook({ ref, tenant, role }).then((headers) => {
            entry.expiresAtMs = Date.now() + (this.#target.auth.refresh?.ttlSeconds ?? 3600) * 1000;
            return headers;
          }).catch((error: unknown) => {
            this.#credentials.delete(ref);
            throw error;
          }),
        };
        this.#credentials.set(ref, entry);
        cached = entry;
      }
      // Probes cannot mutate the credential shared with sibling callers.
      return { ...await cached.headers };
    }
    const secret = credentialEnv ? process.env[credentialEnv] : undefined;
    // TODO(engine): exchange credentials at auth.tokenEndpoint for schemes that
    // need it (oauth2_password, session_cookie). Scaffold returns the header shape.
    switch (scheme) {
      case "bearer":
      case "oauth2_password":
        return { authorization: `Bearer ${secret ?? "«mint-me»"}` };
      case "api_key":
        return { "x-api-key": secret ?? "«mint-me»" };
      case "session_cookie":
        return { cookie: `session=${secret ?? "«mint-me»"}` };
      default:
        return {};
    }
  }

  async #invokeHook(spec: { ref: IdentityRef; tenant: string; role: string }): Promise<Record<string, string>> {
    let onAbort: (() => void) | undefined;
    try {
      const headers = await new Promise<Record<string, string>>((resolve, reject) => {
        onAbort = () => reject(new AuthenticationError("Authentication hook cancelled"));
        this.#signal?.addEventListener("abort", onAbort, { once: true });
        this.#signal?.throwIfAborted();
        if (!this.#customHook) throw new Error("Missing authentication hook");
        Promise.resolve(this.#customHook({
          ...spec,
          ...(this.#signal ? { signal: this.#signal } : {}),
        })).then(resolve, reject);
      });
      if (!headers || typeof headers !== "object" || Array.isArray(headers)) throw new Error();
      const normalized: Record<string, string> = {};
      for (const [name, value] of Object.entries(headers)) {
        const key = name.toLowerCase();
        // These credential headers are already redacted by the audit writer.
        // In particular, hooks cannot override Host or HTTP framing headers.
        if (!["authorization", "cookie", "x-api-key", "x-auth-token"].includes(key) ||
            key in normalized || typeof value !== "string" || !value.trim()) throw new Error();
        validateHeaderValue(key, value);
        normalized[key] = value;
      }
      if (!Object.keys(normalized).length) throw new Error();
      return normalized;
    } catch {
      // Never copy hook exceptions or returned values into scan logs/reports.
      throw new AuthenticationError("Authentication hook failed or returned invalid credential headers");
    } finally {
      if (onAbort) this.#signal?.removeEventListener("abort", onAbort);
    }
  }
}
