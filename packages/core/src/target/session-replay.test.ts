import { expect, it } from "vitest";
import { parseTargetModel, TargetModelSchema } from "@perimeter/sdk";
import { loadTargetModel } from "./loader.js";

it("requires an explicit disposable-session contract and separate bounded login/read/logout routes", async () => {
  const original = await loadTargetModel("examples/target.yaml");
  const target = parseTargetModel({ ...original,
    auth: { scheme: "session_cookie", tokenEndpoint: "/login", login: { format: "json", cookieName: "session" } },
    endpoints: [{ id: "logout", method: "POST", path: "/logout" },
      { id: "profile", method: "GET", path: "/profile", sessionReplay: { readOnly: true, disposableIdentity: true,
        currentSessionOnly: true, identity: "tenantA.user", resultPath: ["id"], expectedValue: "test-user", logoutEndpointId: "logout" } }],
  });
  for (const change of [
    (t: typeof target) => { t.auth = { scheme: "session_cookie" }; },
    (t: typeof target) => { t.auth.scheme = "bearer"; },
    (t: typeof target) => { t.auth.tokenEndpoint = "/profile"; },
    (t: typeof target) => { t.auth.tokenEndpoint = "/logout"; },
    (t: typeof target) => { t.endpoints[0]!.method = "DELETE"; },
    (t: typeof target) => { t.endpoints[0]!.auth = "none"; },
    (t: typeof target) => { t.endpoints[0]!.creates = "session"; },
    (t: typeof target) => { t.endpoints[1]!.method = "POST"; },
    (t: typeof target) => { t.endpoints[1]!.sessionReplay!.identity = "missing"; },
    (t: typeof target) => { t.endpoints[1]!.sessionReplay!.logoutEndpointId = "profile"; },
    (t: typeof target) => { t.endpoints[1]!.sessionReplay!.logoutBody = { padding: "x".repeat(8193) }; },
    (t: typeof target) => { t.identities.push(t.identities.find((i) => i.ref === "tenantA.user")!); },
    (t: typeof target) => { t.endpoints.push(t.endpoints[0]!); },
  ]) { const invalid = structuredClone(target); change(invalid); expect(() => parseTargetModel(invalid)).toThrow(); }
  for (const path of ["//other/logout", "/logout?all=true", "/logout/{id}", "/a/../logout", "/%2e%2e/logout", "/logout#all", "/a\\logout"]) {
    const invalid = structuredClone(target); invalid.endpoints[0]!.path = path;
    expect(() => parseTargetModel(invalid)).toThrow();
  }
  for (const flag of ["readOnly", "disposableIdentity", "currentSessionOnly"]) {
    const invalid = structuredClone(target);
    Object.assign(invalid.endpoints[1]!.sessionReplay!, { [flag]: false });
    expect(() => parseTargetModel(invalid)).toThrow();
  }
  for (const invalid of [{ ...target, baseUrl: "not-a-url" },
    { ...target, auth: { ...target.auth, tokenEndpoint: "http://[" } },
    { ...target, endpoints: target.endpoints.map((e) => e.sessionReplay ? { ...e, path: "http://[" } : e) }]) {
    expect(TargetModelSchema.safeParse(invalid).success).toBe(false);
  }
});

it("requires a separately reviewed anonymous session issuer for fixation", async () => {
  const original = await loadTargetModel("examples/target.yaml");
  const target = parseTargetModel({ ...original,
    auth: { scheme: "session_cookie", tokenEndpoint: "/login", login: { format: "json", cookieName: "session" } },
    endpoints: [{ id: "bootstrap", method: "GET", path: "/login", auth: "none" },
      { id: "logout", method: "POST", path: "/logout" },
      { id: "profile", method: "GET", path: "/profile", sessionReplay: { readOnly: true, disposableIdentity: true,
        currentSessionOnly: true, identity: "tenantA.user", resultPath: ["id"], expectedValue: "test-user", logoutEndpointId: "logout",
        fixation: { bootstrapEndpointId: "bootstrap", issuesAnonymousSession: true } } }],
  });
  for (const change of [
    (t: typeof target) => { t.endpoints[0]!.method = "POST"; },
    (t: typeof target) => { t.endpoints[0]!.auth = "required"; },
    (t: typeof target) => { t.endpoints[0]!.path = "/profile"; },
    (t: typeof target) => { t.endpoints[0]!.path = "/logout"; },
    (t: typeof target) => { t.endpoints[0]!.path = "https://other.example/bootstrap"; },
    (t: typeof target) => { t.endpoints[0]!.path = "/bootstrap?session=unreviewed"; },
    (t: typeof target) => { t.endpoints[0]!.path = "/bootstrap/{id}"; },
    (t: typeof target) => { t.endpoints[0]!.objectRef = { kind: "session", param: "id", ownership: "user" }; },
    (t: typeof target) => { t.endpoints.push(t.endpoints[0]!); },
    (t: typeof target) => { t.endpoints[2]!.sessionReplay!.fixation!.bootstrapEndpointId = "missing"; },
    (t: typeof target) => { Object.assign(t.endpoints[2]!.sessionReplay!.fixation!, { issuesAnonymousSession: false }); },
  ]) { const invalid = structuredClone(target); change(invalid); expect(TargetModelSchema.safeParse(invalid).success).toBe(false); }
});
