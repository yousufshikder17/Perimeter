import { expect, it } from "vitest";
import { parseTargetModel } from "@perimeter/sdk";
import { loadTargetModel } from "./loader.js";

it("validates explicit same-tenant role boundaries and unambiguous read-only control routes", async () => {
  const original = await loadTargetModel("examples/target.yaml");
  const target = parseTargetModel({ ...original, endpoints: [
    { id: "profile", method: "GET", path: "/profile" },
    { id: "admin", method: "GET", path: "/admin/report", roleAccess: { readOnly: true, deniedByPolicy: true,
      allowedIdentity: "tenantA.admin", deniedIdentity: "tenantA.user", resultPath: ["reportId"],
      control: { endpointId: "profile", resultPath: ["id"], expectedValue: "member-id" } } },
  ] });
  for (const change of [
    (t: typeof target) => { t.endpoints[1]!.method = "POST"; },
    (t: typeof target) => { t.endpoints[1]!.auth = "none"; },
    (t: typeof target) => { t.endpoints[1]!.roleAccess!.allowedIdentity = "missing"; },
    (t: typeof target) => { t.endpoints[1]!.roleAccess!.deniedIdentity = "tenantB.user"; },
    (t: typeof target) => { t.endpoints[1]!.roleAccess!.deniedIdentity = "tenantA.admin"; },
    (t: typeof target) => { t.identities.find((i) => i.ref === "tenantA.admin")!.role = "member"; },
    (t: typeof target) => { t.endpoints[1]!.roleAccess!.control.endpointId = "admin"; },
    (t: typeof target) => { t.endpoints[0]!.path = "/admin/report"; },
    (t: typeof target) => { t.endpoints[0]!.method = "POST"; },
    (t: typeof target) => { t.endpoints[0]!.auth = "none"; },
    (t: typeof target) => { t.endpoints.push(t.endpoints[0]!); },
    (t: typeof target) => { t.identities.push(t.identities[0]!); },
    (t: typeof target) => { t.endpoints[1]!.objectRef = { kind: "report", param: "id", ownership: "user" }; },
  ]) { const invalid = structuredClone(target); change(invalid); expect(() => parseTargetModel(invalid)).toThrow(); }
  for (const path of ["//elsewhere/admin", "/admin/{id}", "/admin/../report", "/%2e%2e/admin", "/admin?all=true", "/admin#fragment", "/admin\\report"]) {
    const invalid = structuredClone(target); invalid.endpoints[1]!.path = path;
    expect(() => parseTargetModel(invalid)).toThrow();
  }
});
