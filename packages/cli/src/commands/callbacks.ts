import { Command, Option } from "clipanion";
import { startCallbackCollector } from "@perimeter/core";

export class CallbacksServeCommand extends Command {
  static override paths = [["callbacks", "serve"]];
  static override usage = Command.Usage({ description: "Collect minimal receipts on two operator-owned callback ports." });
  out = Option.String("--out", { required: true, description: "New NDJSON receipt file; existing files are never overwritten." });
  host = Option.String("--host", "127.0.0.1");
  controlPort = Option.String("--control-port", "9001");
  prohibitedPort = Option.String("--prohibited-port", "9002");
  duration = Option.String("--duration-seconds", "3600");
  acknowledgeExposure = Option.Boolean("--acknowledge-exposure", false);

  async execute(): Promise<number> {
    const seconds = Number(this.duration);
    if (!Number.isInteger(seconds) || seconds < 1 || seconds > 86400) throw new Error("Duration must be 1–86400 seconds");
    const collector = await startCallbackCollector({ receiptFile: this.out, host: this.host,
      controlPort: Number(this.controlPort), prohibitedPort: Number(this.prohibitedPort), acknowledgeExposure: this.acknowledgeExposure });
    this.context.stdout.write(JSON.stringify({ controlOrigin: collector.controlOrigin, prohibitedOrigin: collector.prohibitedOrigin, receiptFile: this.out }) + "\n");
    try {
      await new Promise<void>((resolve) => {
        const finish = () => { clearTimeout(timer); process.removeListener("SIGINT", finish); process.removeListener("SIGTERM", finish); resolve(); };
        const timer = setTimeout(finish, seconds * 1000);
        process.once("SIGINT", finish); process.once("SIGTERM", finish);
      });
    } finally { await collector.stop(); }
    return 0;
  }
}
