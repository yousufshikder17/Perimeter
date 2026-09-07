import { z } from "zod";
import { validateHeaderValue } from "node:http";
import type { GuardedHttpClient, TargetModel } from "@perimeter/sdk";
import { AuthenticationError } from "./identity-manager.js";

export type ExchangeCredential = (ref: string, credentialEnv?: string) => Promise<{
  headers: Record<string, string>; ttlSeconds: number;
}>;

const OAuthCredentials = z.object({
  username: z.string().min(1), password: z.string().min(1),
  client_id: z.string().min(1).optional(), client_secret: z.string().min(1).optional(),
  scope: z.string().optional(),
}).strict();
const TokenResponse = z.object({
  access_token: z.string().min(1), token_type: z.string().regex(/^Bearer$/i),
  expires_in: z.number().positive().finite().optional(), refresh_token: z.string().min(1).optional(),
});

/** The manager caches access credentials; this closure retains only per-identity refresh tokens. */
export function createTokenExchange(target: TargetModel, http: GuardedHttpClient): ExchangeCredential {
  const refreshTokens = new Map<string, string>();
  return async (ref, credentialEnv) => {
    try {
      const raw = credentialEnv ? process.env[credentialEnv] : undefined;
      if (!raw?.trim()) throw new Error();
      const fields = z.record(z.string()).parse(JSON.parse(raw));
      if (!Object.keys(fields).length) throw new Error();
      let endpoint = target.auth.tokenEndpoint!;
      let body: string;
      let contentType = "application/x-www-form-urlencoded";
      if (target.auth.scheme === "oauth2_password") {
        const credentials = OAuthCredentials.parse(fields);
        const refresh = refreshTokens.get(ref);
        const parameters = new URLSearchParams();
        if (refresh) {
          endpoint = target.auth.refresh?.endpoint ?? endpoint;
          parameters.set("grant_type", "refresh_token");
          parameters.set("refresh_token", refresh);
        } else {
          parameters.set("grant_type", "password");
          parameters.set("username", credentials.username);
          parameters.set("password", credentials.password);
        }
        for (const key of ["client_id", "client_secret", "scope"] as const) {
          if (credentials[key] !== undefined) parameters.set(key, credentials[key]);
        }
        body = parameters.toString();
      } else {
        if (target.auth.login?.format === "json") {
          contentType = "application/json";
          body = JSON.stringify(fields);
        } else body = new URLSearchParams(fields).toString();
      }
      const response = await http.request({ method: "POST", url: endpoint,
        headers: { "content-type": contentType }, body });
      if (response.status < 200 || response.status >= 300) throw new Error();
      const configuredTtl = target.auth.refresh?.ttlSeconds ?? 3600;
      if (target.auth.scheme === "oauth2_password") {
        const token = TokenResponse.parse(await response.json());
        validateHeaderValue("authorization", `Bearer ${token.access_token}`);
        if (token.refresh_token) refreshTokens.set(ref, token.refresh_token);
        return { headers: { authorization: `Bearer ${token.access_token}` },
          ttlSeconds: Math.min(configuredTtl, token.expires_in ?? configuredTtl) };
      }
      const name = target.auth.login!.cookieName;
      const matching = (response.setCookies ?? []).filter((cookie) => cookie.startsWith(`${name}=`));
      if (matching.length !== 1) throw new Error();
      const cookie = matching[0]!.split(";")[0]!;
      if (!cookie.slice(name.length + 1)) throw new Error();
      validateHeaderValue("cookie", cookie);
      const maxAge = /;\s*max-age=(-?\d+)/i.exec(matching[0]!);
      const expires = /;\s*expires=([^;]+)/i.exec(matching[0]!);
      const lifetime = maxAge ? Number(maxAge[1]) : expires ? (Date.parse(expires[1]!) - Date.now()) / 1000 : configuredTtl;
      if (!Number.isFinite(lifetime) || lifetime <= 0) throw new Error();
      return { headers: { cookie }, ttlSeconds: Math.min(configuredTtl, lifetime) };
    } catch {
      refreshTokens.delete(ref);
      // Never surface server payloads, credential fields, or HTTP client errors.
      throw new AuthenticationError("Authentication exchange failed; check the configured credentials and login contract");
    }
  };
}
