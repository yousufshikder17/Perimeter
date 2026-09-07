import { describe, expect, it, vi } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel } from "../target/loader.js";
import { AuthenticationError, IdentityManager } from "./identity-manager.js";

it("rejects missing or blank environment credentials without caching placeholders", async () => {
  const target = await loadTargetModel("examples/target.yaml");
  const spec = target.identities[0]!;
  const key = "PERIMETER_TEST_STATIC_CREDENTIAL";
  try {
    for (const scheme of ["bearer", "api_key", "session_cookie"] as const) {
      target.auth = { scheme };
      spec.credentials = { env: key };
      const identity = new IdentityManager(target).get(spec.ref);
      for (const secret of [undefined, "", " \t "]) {
        vi.stubEnv(key, secret);
        await expect(identity.headers()).rejects.toThrow(AuthenticationError);
        await expect(identity.headers()).rejects.toThrow(`set a non-blank ${key}`);
      }
      vi.stubEnv(key, "test-credential");
      expect(await identity.headers()).toEqual(
        scheme === "api_key" ? { "x-api-key": "test-credential" }
          : scheme === "session_cookie" ? { cookie: "session=test-credential" }
            : { authorization: "Bearer test-credential" },
      );
      vi.stubEnv(key, undefined);
      await expect(identity.headers()).rejects.toThrow(AuthenticationError);
      delete spec.credentials;
      await expect(new IdentityManager(target).get(spec.ref).headers())
        .rejects.toThrow("configure credentials.env");
    }
  } finally {
    vi.unstubAllEnvs();
  }
});

describe("custom credential lifecycle", () => {
  it("isolates identities, coalesces concurrent mints, and refreshes retained handles", async () => {
    const target = await loadTargetModel("examples/target.yaml");
    target.auth = { scheme: "custom", refresh: { ttlSeconds: 1 } };
    expect(() => parseTargetModel(target)).not.toThrow();
    expect(() => parseTargetModel({ ...target, auth: { ...target.auth, scheme: "bearer" } }))
      .toThrow("refresh.endpoint");
    const calls: string[] = [];
    const manager = new IdentityManager(target, async ({ ref }) => {
      calls.push(ref);
      return { Authorization: `Bearer ${ref}-${calls.length}` };
    });
    const a = manager.get(target.identities[0]!.ref);
    const b = manager.get(target.identities[1]!.ref);
    const now = vi.spyOn(Date, "now").mockReturnValue(1000);
    try {
      const [first, second] = await Promise.all([a.headers(), a.headers()]);
      expect(calls).toEqual([a.ref]);
      expect(first).toEqual(second);
      first.authorization = "changed by caller";
      expect(await a.headers()).toEqual(second);
      expect(await b.headers()).not.toEqual(second);
      now.mockReturnValue(2000);
      const [renewed, concurrent] = await Promise.all([a.headers(), a.headers()]);
      expect(renewed).toEqual(concurrent);
      expect(renewed).not.toEqual(second);
      expect(calls).toEqual([a.ref, b.ref, a.ref]);
    } finally {
      now.mockRestore();
    }
  });

  it("rejects unsafe results, redacts failures, retries failures, and respects cancellation", async () => {
    const target = await loadTargetModel("examples/target.yaml");
    target.auth = { scheme: "custom" };
    const ref = target.identities[0]!.ref;
    for (const headers of [
      {}, { host: "other.example" }, { "x-secret": "secret" },
      { authorization: "Bearer secret\r\nHost: other.example" },
      { authorization: "" }, { authorization: "a", Authorization: "b" },
    ]) {
      await expect(new IdentityManager(target, async () => headers).get(ref).headers())
        .rejects.toThrow(AuthenticationError);
    }
    let calls = 0;
    const manager = new IdentityManager(target, async () => {
      if (++calls === 1) throw new Error("credential-secret");
      return { cookie: "session=ok" };
    });
    await expect(manager.get(ref).headers()).rejects.toThrow(
      /^Authentication hook failed or returned invalid credential headers$/,
    );
    expect(await manager.get(ref).headers()).toEqual({ cookie: "session=ok" });
    expect(calls).toBe(2);

    const controller = new AbortController();
    const blocked = new IdentityManager(target, ({ signal }) => {
      expect(signal).toBe(controller.signal);
      return new Promise(() => {});
    }, controller.signal);
    const pending = blocked.get(ref).headers();
    controller.abort();
    await expect(pending).rejects.toThrow(AuthenticationError);
  });
});
