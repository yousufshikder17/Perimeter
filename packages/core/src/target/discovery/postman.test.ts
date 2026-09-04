import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverFromPostman } from "./postman.js";

let directory: string | undefined;

afterEach(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
});

describe("Postman discovery", () => {
  it("flattens requests into a conservative review-required inventory", async () => {
    directory = await mkdtemp(join(tmpdir(), "perimeter-postman-"));
    const collection = join(directory, "collection.json");
    await writeFile(
      collection,
      JSON.stringify({
        auth: { type: "bearer" },
        item: [
          {
            name: "Accounts",
            item: [
              { name: "Get account", request: { method: "GET", url: "{{baseUrl}}/accounts/:id" } },
              { name: "Duplicate", request: { method: "GET", url: "{{baseUrl}}/accounts/:id" } },
            ],
          },
          {
            name: "Login",
            request: {
              auth: { type: "noauth" },
              method: "POST",
              url: { path: ["auth", "login"] },
            },
          },
        ],
      }),
    );

    const result = await discoverFromPostman(collection);

    expect(result.endpoints).toEqual([
      expect.objectContaining({
        id: "get_accounts_id",
        method: "GET",
        path: "/accounts/{id}",
        auth: "required",
      }),
      expect.objectContaining({
        id: "post_auth_login",
        method: "POST",
        path: "/auth/login",
        auth: "none",
        rateSensitive: true,
      }),
    ]);
    expect(result.reviewNotes).toContain(
      'get_accounts_id: confirm objectRef ownership for path param "id"',
    );
  });
});
