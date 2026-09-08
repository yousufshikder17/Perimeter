import { createInterface } from "node:readline";
import process from "node:process";
import { setInterval } from "node:timers";
const mode = process.argv[2] ?? "ok";
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const receive = async () => JSON.parse((await lines.next()).value);
const send = (message) => process.stdout.write(JSON.stringify(message) + "\n");
const start = await receive();
if (start.version !== 1 || start.target.auth || process.env.PERIMETER_ISOLATION_TEST_SECRET ||
    JSON.stringify(start).includes("PERIMETER_ISOLATION_TEST_SECRET")) process.exit(2);
if (mode === "crash") throw new Error("worker-private-error");
if (mode === "hang") { await new Promise(() => setInterval(() => {}, 1000)); }
if (mode === "flood") { process.stdout.write("x".repeat(300000)); await new Promise(() => setInterval(() => {}, 1000)); }
if (mode === "bad-frame") { send({ type: "arbitrary-code", text: "worker-private-error" }); process.exit(0); }
const identity = start.target.identities[0]?.ref;
const request = { method: "GET", url: "/profile", as: identity };
if (mode === "identity") request.as = "not-granted";
if (mode === "header") request.headers = { host: "other.example" };
if (mode === "offhost") request.url = "http://127.0.0.1:1/blocked";
if (mode === "write") request.method = "DELETE";
if (mode === "slow") request.url = "/slow";
if (mode === "large") request.url = "/large";
send({ type: "request", id: 0, request });
const response = await receive();
if (mode === "offhost" || mode === "large") {
  if (response.ok) process.exit(3);
} else {
  if (!response.ok || JSON.stringify(response).includes("isolation-secret-token")) process.exit(4);
  const ref = mode === "fake-evidence" ? "never-observed" : response.exchange.ref;
  send({ type: "finding", endpointId: "profile", locator: "fixture-check", title: "Fixture result", severity: "LOW", confidence: "TENTATIVE",
    summary: "Test fixture observes a response.", exchangeRefs: [ref], remediation: { guidance: "Test only", references: [] } });
  if (mode === "budget") {
    send({ type: "request", id: 1, request });
    if ((await receive()).ok) process.exit(5);
  }
}
send({ type: "done", version: 1 });
process.stdin.destroy();
