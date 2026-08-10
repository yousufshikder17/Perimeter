import type { Identity, IdentityRef, TargetModel, AuthScheme } from "@perimeter/sdk";

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
}) => Promise<Record<string, string>>;

interface CachedIdentity {
  identity: Identity;
  expiresAtMs: number;
}

export class IdentityManager {
  readonly #target: TargetModel;
  readonly #customHook: CustomAuthHook | undefined;
  readonly #cache = new Map<IdentityRef, CachedIdentity>();

  constructor(target: TargetModel, customHook?: CustomAuthHook) {
    this.#target = target;
    this.#customHook = customHook;
  }

  get(ref: IdentityRef): Identity {
    const cached = this.#cache.get(ref);
    if (cached && cached.expiresAtMs > Date.now()) return cached.identity;

    const spec = this.#target.identities.find((i) => i.ref === ref);
    if (!spec) throw new Error(`unknown identity ref "${ref}" (not in Target Model)`);

    const identity: Identity = {
      ref,
      tenant: spec.tenant,
      role: spec.role,
      headers: async () =>
        this.#mint(this.#target.auth.scheme, spec.ref, spec.tenant, spec.role, spec.credentials?.env),
    };

    const ttlMs = (this.#target.auth.refresh?.ttlSeconds ?? 3600) * 1000;
    this.#cache.set(ref, { identity, expiresAtMs: Date.now() + ttlMs });
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
      if (!this.#customHook) throw new Error(`auth scheme "custom" requires a customHook`);
      return this.#customHook({ ref, tenant, role });
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
}
