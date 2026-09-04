import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverFromHar } from "./har.js";

let directory: string | undefined;

afterEach(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
});

describe("HAR discovery", () => {
  it("deduplicates captures and marks inferred paths for review", async () => {
    directory = await mkdtemp(join(tmpdir(), "perimeter-har-"));
    const capture = join(directory, "capture.har");
    await writeFile(
      capture,
      JSON.stringify({
        log: {
          entries: [
            {
              request: {
                method: "GET",
                url: "https://staging.example.com/accounts/123?expand=owner",
                headers: [{ name: "Authorization", value: "Bearer redacted" }],
              },
            },
            {
              request: {
                method: "GET",
                url: "https://staging.example.com/accounts/456",
                headers: [],
              },
            },
            {
              request: {
                method: "POST",
                url: "https://staging.example.com/auth/login",
                headers: [],
              },
            },
          ],
        },
      }),
    );

    const result = await discoverFromHar(capture);

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
        auth: "optional",
        rateSensitive: true,
      }),
    ]);
    expect(result.reviewNotes).toContain(
      "get_accounts_id: confirm inferred {id} path template and ownership",
    );
  });
});
