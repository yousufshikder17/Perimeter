/**
 * @perimeter/core — the open-source core runtime (spec §2, §4, §6).
 *
 * Orchestrator, execution engine, the safety guard + rate governance, the audit
 * log, identity/fixture management, the Target Model loader + OpenAPI discovery,
 * the finding registry, and the reporters.
 */

export const CORE_VERSION = "0.1.0" as const;

// Orchestration & engine
export { Orchestrator, type OrchestratorOptions } from "./orchestrator.js";
export { ExecutionEngine } from "./engine/execution-engine.js";
export { createIsolatedProbe, IsolatedProbeError } from "./isolation/probe.js";
export { IsolatedProbeSchema, ISOLATED_PROTOCOL_VERSION, type IsolatedProbeConfig } from "./isolation/protocol.js";
export { selectProbes, type Selection } from "./engine/scheduler.js";

// Config
export { ScanConfigSchema, parseScanConfig, type ScanConfig } from "./config/scan-config.js";
export { readConfigFile } from "./config/read-file.js";

// Safety
export { SafetyGuard, SafetyViolation, type GuardPolicy } from "./safety/guard.js";
export { RateLimiter, type RateLimitConfig } from "./safety/rate-limiter.js";
export { inspectOutboundPayload, isReadOnlyMethod } from "./safety/outbound-inspector.js";

// HTTP
export { GuardedHttpClientImpl, type GuardedHttpClientDeps } from "./http/guarded-http-client.js";

// Audit & evidence
export {
  NdjsonAuditLog,
  MemoryAuditLog,
  type AuditSink,
  type AuditEntry,
} from "./audit/audit-log.js";
export { redactHeaders, redactBody, MAX_CAPTURED_BODY_BYTES } from "./audit/redaction.js";

// Identity & fixtures
export { IdentityManager, type CustomAuthHook } from "./identity/identity-manager.js";
export { FixtureManager, type ScratchObject } from "./identity/fixtures.js";

// Target model
export { loadTargetModel } from "./target/loader.js";
export {
  discoverFromOpenApi,
  type DiscoveryResult,
  type DraftEndpoint,
} from "./target/discovery/openapi.js";
export { discoverFromPostman } from "./target/discovery/postman.js";
export { discoverFromHar } from "./target/discovery/har.js";
export { discoverFromCrawl, type CrawlOptions } from "./target/discovery/crawl.js";

// Findings
export { FindingRegistryImpl, type Baseline } from "./findings/registry.js";
export {
  BASELINE_SCHEMA_VERSION,
  BaselineFileSchema,
  createBaselineFile,
  loadBaseline,
  type BaselineFile,
} from "./findings/baseline.js";
export { computeFingerprint } from "./findings/fingerprint.js";
export {
  COMPARISON_SCHEMA_VERSION,
  compareScans,
  renderComparisonJson,
  renderComparisonMarkdown,
  renderComparisonHtml,
  type ScanComparison,
} from "./findings/comparison.js";

// Reporters
export * from "./reporters/index.js";

// Runtime primitives (also useful for the probe test harness)
export { DeterministicRng } from "./runtime/rng.js";
export { SystemClock, VirtualClock } from "./runtime/clock.js";
export { ConsoleLogger } from "./runtime/logger.js";
export { MutableBudget } from "./runtime/budget.js";

// Probe test harness (spec §3.4) — recorded-fixture mode for contributor tests
export {
  runProbeAgainstFixtures,
  type RecordedExchange,
  type HarnessOptions,
  type HarnessResult,
} from "./testing/harness.js";
