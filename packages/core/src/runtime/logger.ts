import type { Logger } from "@perimeter/sdk";

type Level = "debug" | "info" | "warn" | "error";
const ORDER: Record<Level, number> = { debug: 0, info: 1, warn: 2, error: 3 };

/** Minimal structured logger. Swap for pino/etc. behind the same interface. */
export class ConsoleLogger implements Logger {
  readonly #min: number;
  readonly #bindings: Record<string, unknown>;

  constructor(minLevel: Level = "info", bindings: Record<string, unknown> = {}) {
    this.#min = ORDER[minLevel];
    this.#bindings = bindings;
  }

  #log(level: Level, msg: string, meta?: Record<string, unknown>): void {
    if (ORDER[level] < this.#min) return;
    const line = {
      level,
      time: new Date().toISOString(),
      msg,
      ...this.#bindings,
      ...meta,
    };
    const stream = level === "error" || level === "warn" ? process.stderr : process.stdout;
    stream.write(`${JSON.stringify(line)}\n`);
  }

  debug(msg: string, meta?: Record<string, unknown>): void {
    this.#log("debug", msg, meta);
  }
  info(msg: string, meta?: Record<string, unknown>): void {
    this.#log("info", msg, meta);
  }
  warn(msg: string, meta?: Record<string, unknown>): void {
    this.#log("warn", msg, meta);
  }
  error(msg: string, meta?: Record<string, unknown>): void {
    this.#log("error", msg, meta);
  }
  child(bindings: Record<string, unknown>): Logger {
    const level = (Object.keys(ORDER) as Level[]).find((l) => ORDER[l] === this.#min) ?? "info";
    return new ConsoleLogger(level, { ...this.#bindings, ...bindings });
  }
}
