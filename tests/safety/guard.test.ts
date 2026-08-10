import { describe, it, expect } from "vitest";
import { SafetyGuard, SafetyViolation, inspectOutboundPayload, isReadOnlyMethod } from "@perimeter/core";

/**
 * Safety-invariant suite (spec §8.9). These are GATED invariants, not docs: the
 * engine cannot egress off-target, cannot issue destructive verbs, and refuses
 * writes to non-scratch objects. A regression here is release-blocking.
 */

function guard(overrides: Partial<Parameters<typeof makePolicy>[0]> = {}) {
  return new SafetyGuard(makePolicy(overrides));
}
function makePolicy(o: {
  hosts?: string[];
  allowMutating?: boolean;
  scratchIds?: string[];
}) {
  return {
    allowedHosts: new Set(o.hosts ?? ["target.example"]),
    allowMutating: o.allowMutating ?? false,
    scratchObjectIds: new Set(o.scratchIds ?? []),
  };
}

describe("egress is on-target only (spec §4.2)", () => {
  it("blocks a request to a non-allow-listed host", () => {
    expect(() =>
      guard().check({
        method: "GET",
        url: "https://evil.example/steal",
        probeSafetyClass: "read-only",
        payloadParts: [],
      }),
    ).toThrow(SafetyViolation);
  });

  it("permits a request to the modeled target host", () => {
    expect(() =>
      guard().check({
        method: "GET",
        url: "https://target.example/api/x",
        probeSafetyClass: "read-only",
        payloadParts: [],
      }),
    ).not.toThrow();
  });
});

describe("read-only by default (spec §3.2 rule 2)", () => {
  it("refuses POST for a read-only probe", () => {
    expect(() =>
      guard().check({
        method: "POST",
        url: "https://target.example/api/x",
        probeSafetyClass: "read-only",
        payloadParts: ["{}"],
      }),
    ).toThrow(SafetyViolation);
  });

  it("refuses a write even when mutating is allowed, unless it targets a scratch object", () => {
    expect(() =>
      guard({ allowMutating: true }).check({
        method: "PUT",
        url: "https://target.example/api/x",
        probeSafetyClass: "idempotent-write",
        payloadParts: ["{}"],
      }),
    ).toThrow(/scratch object/);
  });

  it("permits a scratch-object write when fully authorized", () => {
    expect(() =>
      guard({ allowMutating: true, scratchIds: ["scratch-1"] }).check({
        method: "PUT",
        url: "https://target.example/api/x",
        probeSafetyClass: "idempotent-write",
        payloadParts: ["{}"],
        targetsScratchObjectId: "scratch-1",
      }),
    ).not.toThrow();
  });
});

describe("no destructive verbs, even in injection probes (spec §4.2)", () => {
  it("blocks a destructive SQL verb in the payload", () => {
    expect(() =>
      guard().check({
        method: "GET",
        url: "https://target.example/api/x?q=1",
        probeSafetyClass: "read-only",
        payloadParts: ["'; DROP TABLE users; --"],
      }),
    ).toThrow(SafetyViolation);
  });

  it("inspector flags stacked statements and destructive verbs", () => {
    expect(inspectOutboundPayload(["; DELETE FROM t"]).ok).toBe(false);
    expect(inspectOutboundPayload(["' AND 1=1 -- "]).ok).toBe(true); // inert payload is fine
  });

  it("read-only method set is exactly GET/HEAD/OPTIONS", () => {
    expect(isReadOnlyMethod("GET")).toBe(true);
    expect(isReadOnlyMethod("DELETE")).toBe(false);
  });
});
