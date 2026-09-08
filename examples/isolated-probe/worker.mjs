import { createInterface } from "node:readline";
import process from "node:process";

// A protocol-v1 worker has no target network client or credential access.
// Perimeter reads stdout as protocol frames; diagnostics belong on stderr.
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const receive = async () => JSON.parse((await lines.next()).value);
const send = (message) => process.stdout.write(JSON.stringify(message) + "\n");
const start = await receive();
if (start.type !== "start" || start.version !== 1) process.exit(1);
const endpoint = start.target.endpoints.find((entry) => entry.method === "GET" && !entry.path.includes("{"));
if (endpoint) {
  send({ type: "request", id: 0, request: { method: "GET", url: endpoint.path } });
  const response = await receive();
  // This sample records a diagnostic, not a claim that authentication is secure.
  if (response.ok) send({ type: "pass", endpointId: endpoint.id, title: "Worker transport diagnostic",
    summary: `Observed HTTP ${response.exchange.response.status} through the parent-owned guarded client.` });
}
send({ type: "done", version: 1 });
process.stdin.destroy();
