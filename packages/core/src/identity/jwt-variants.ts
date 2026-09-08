import { decodeJwt, decodeProtectedHeader } from "jose";
import { isDeepStrictEqual } from "node:util";
import type { IdentitySpec, JwtVariant, TargetModel } from "@perimeter/sdk";

/** Construct only local test credentials; decoding does not verify signatures. */
export function createJwtVariants(
  headers: Record<string, string>, target: TargetModel, spec: IdentitySpec, nowMs = Date.now(),
): Partial<Record<JwtVariant, Record<string, string>>> {
  // Extra credentials could authenticate independently and invalidate the control.
  const token = Object.keys(headers).length === 1 ? /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(headers.authorization ?? "")?.[1] : undefined;
  let original;
  try { original = token ? readSignedJwt(token) : undefined; } catch { /* Opaque/non-JWT credentials are inapplicable. */ }
  if (!token || !original) {
    if (spec.expiredCredentials) throw new Error("Expired JWT testing requires a single signed Bearer credential");
    return {};
  }
  const [header, payload, signature] = token.split(".");
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const bearer = (value: string) => ({ authorization: `Bearer ${value}` });
  const variants: Partial<Record<JwtVariant, Record<string, string>>> = {
    "none-alg": bearer(`${encode({ ...original.header, alg: "none" })}.${payload}.`),
    "signature-stripped": bearer(`${header}.${payload}.`),
  };
  const discriminator = target.tenancy.discriminator;
  const otherTenant = target.tenancy.tenants.find((tenant) => tenant !== spec.tenant);
  if (discriminator.location === "jwt_claim" && otherTenant && original.claims[discriminator.name] === spec.tenant) {
    // Retain the signature: acceptance tests integrity, not a proven cross-tenant data leak.
    variants["tenant-swapped"] = bearer(`${header}.${encode({ ...original.claims, [discriminator.name]: otherTenant })}.${signature}`);
  }
  if (spec.expiredCredentials) {
    const expired = process.env[spec.expiredCredentials.env];
    if (!expired) throw new Error("Missing expired JWT credential");
    const sample = readSignedJwt(expired);
    const exp = sample.claims.exp;
    const principalClaims = (claims: typeof sample.claims) => Object.fromEntries(
      Object.entries(claims).filter(([name]) => !["exp", "iat", "nbf", "jti"].includes(name)),
    );
    if (typeof exp !== "number" || !Number.isFinite(exp) || exp > nowMs / 1000 - 60 ||
        !isDeepStrictEqual(principalClaims(sample.claims), principalClaims(original.claims)) || sample.header.alg !== original.header.alg) {
      throw new Error("Expired JWT must match the live principal and be expired for at least 60 seconds");
    }
    variants.expired = bearer(expired);
  }
  return variants;
}

function readSignedJwt(token: string) {
  if (token.length > 16 * 1024 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error("Invalid JWT");
  const header = decodeProtectedHeader(token);
  if (!header.alg || header.alg.toLowerCase() === "none" || header.b64 === false) throw new Error("Signed JWT required");
  return { header, claims: decodeJwt(token) };
}
