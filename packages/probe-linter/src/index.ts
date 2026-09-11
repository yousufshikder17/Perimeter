import { readFile } from "node:fs/promises";
import { ProbeManifestSchema } from "@perimeter/sdk";

/**
 * Probe linter (spec §3.4). Statically enforces the §3.2 safety contract so a
 * probe cannot even be authored around the guard. Run in CI; a violation is a
 * release-blocking defect (spec §10 risk 1).
 *
 * This is a source-text linter (fast, dependency-light). The engine's runtime
 * guard is the real guarantee; the linter catches problems at author time.
 */

export type Severity = "error" | "warning";

export interface LintFinding {
  file: string;
  line: number;
  rule: string;
  severity: Severity;
  message: string;
}

export interface LintRule {
  name: string;
  /** Return findings for a single probe source file. */
  check(file: string, source: string): LintFinding[];
}

// --- Rule: no raw network egress (spec §3.2 rule 1) -------------------------
const NO_RAW_EGRESS: LintRule = {
  name: "no-raw-egress",
  check(file, source) {
    const out: LintFinding[] = [];
    const patterns: Array<[RegExp, string]> = [
      [/\bfetch\s*\(/, "raw fetch() is forbidden — use ctx.http"],
      [/from\s+["']node:https?["']/, "importing node:http/https is forbidden — use ctx.http"],
      [/from\s+["']undici["']/, "importing undici directly is forbidden — use ctx.http"],
      [/from\s+["']axios["']/, "importing an HTTP library directly is forbidden — use ctx.http"],
      [/\bnew\s+XMLHttpRequest\b/, "XMLHttpRequest is forbidden — use ctx.http"],
    ];
    eachLine(source, (line, n) => {
      for (const [re, msg] of patterns) {
        if (re.test(line)) out.push({ file, line: n, rule: this.name, severity: "error", message: msg });
      }
    });
    return out;
  },
};

// --- Rule: deterministic RNG only (spec §3.2 rule 4) ------------------------
const NO_NONDETERMINISM: LintRule = {
  name: "deterministic-only",
  check(file, source) {
    const out: LintFinding[] = [];
    eachLine(source, (line, n) => {
      if (/\bMath\.random\s*\(/.test(line)) {
        out.push({ file, line: n, rule: this.name, severity: "error", message: "Math.random() is forbidden — use ctx.rng" });
      }
      // Flag wall-clock reads used for control flow. Formatting a timestamp for a
      // finding field (`new Date().toISOString()`) is not control flow, so allow
      // lines that only format the clock to a string (spec §3.2 rule 4).
      const isTimestampFormat = /\.toISOString\s*\(/.test(line);
      if (!isTimestampFormat && (/\bDate\.now\s*\(/.test(line) || /\bnew\s+Date\s*\(\s*\)/.test(line))) {
        out.push({ file, line: n, rule: this.name, severity: "error", message: "wall-clock read is forbidden for control flow — use ctx.clock" });
      }
    });
    return out;
  },
};

// --- Rule: evidence on finding (spec §3.2 rule 3, §6.2) ---------------------
const EVIDENCE_ON_FINDING: LintRule = {
  name: "evidence-on-finding",
  check(file, source) {
    // Heuristic: a report({...}) object literal that has `severity` (i.e. a
    // Finding, not a Pass) must also mention `evidence`.
    const out: LintFinding[] = [];
    const re = /report\s*\(\s*\{([\s\S]*?)\}\s*\)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(source))) {
      const body = m[1] ?? "";
      if (/\bseverity\b/.test(body) && !/\bevidence\b/.test(body)) {
        out.push({
          file,
          line: lineAt(source, m.index),
          rule: this.name,
          severity: "error",
          message: "report() of a Finding must include an evidence bundle (no evidence, no finding)",
        });
      }
    }
    return out;
  },
};

export const DEFAULT_RULES: LintRule[] = [NO_RAW_EGRESS, NO_NONDETERMINISM, EVIDENCE_ON_FINDING];

export function lintSource(file: string, source: string, rules = DEFAULT_RULES): LintFinding[] {
  return rules.flatMap((r) => r.check(file, source));
}

export async function lintFile(file: string, rules = DEFAULT_RULES): Promise<LintFinding[]> {
  return lintSource(file, await readFile(file, "utf8"), rules);
}

/** Validate a probe manifest object (spec §3.1) — completeness + destructive ban. */
export function lintManifest(file: string, manifest: unknown): LintFinding[] {
  const parsed = ProbeManifestSchema.safeParse(manifest);
  if (!parsed.success) {
    return [{ file, line: 1, rule: "manifest-complete", severity: "error", message: parsed.error.message }];
  }
  const out: LintFinding[] = [];
  if (parsed.data.safety.destructive) {
    out.push({ file, line: 1, rule: "no-destructive", severity: "error", message: "safety.destructive must be false for standard-library acceptance (spec §3.1)" });
  }
  if (parsed.data.safety.class === "mutating") {
    out.push({ file, line: 1, rule: "no-mutating", severity: "warning", message: "safety.class 'mutating' requires operator opt-in and reviewed scratch-only effects" });
  }
  return out;
}

// --- helpers ----------------------------------------------------------------
function eachLine(source: string, fn: (line: string, n: number) => void): void {
  source.split(/\r?\n/).forEach((line, i) => fn(line, i + 1));
}
function lineAt(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}
