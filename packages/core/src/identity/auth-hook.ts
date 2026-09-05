import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { TargetModel } from "@perimeter/sdk";
import type { CustomAuthHook } from "./identity-manager.js";

/** Operator-owned local code, resolved relative to the reviewed Target Model. */
export async function loadAuthHook(
  target: TargetModel,
  targetPath: string,
): Promise<CustomAuthHook | undefined> {
  if (target.auth.scheme !== "custom") return undefined;
  const path = target.auth.customHook;
  if (!path?.trim()) throw new Error('auth scheme "custom" requires auth.customHook');
  if (/^[a-z][a-z\d+.-]*:/i.test(path) && !/^[a-z]:[\\/]/i.test(path)) {
    throw new Error("auth.customHook must be a local filesystem path");
  }
  const url = pathToFileURL(resolve(dirname(resolve(targetPath)), path));
  let hook: unknown;
  try {
    const mod = (await import(url.href)) as { default?: unknown };
    hook = mod.default;
  } catch {
    // Module initialization errors can contain credentials. Never echo them.
    throw new Error("Could not load auth.customHook; check its local path and runtime support");
  }
  if (typeof hook !== "function") {
    throw new Error("auth.customHook must default-export a function");
  }
  return hook as CustomAuthHook;
}
