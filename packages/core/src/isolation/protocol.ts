import { z } from "zod";
import { Confidence, GrpcRequestSchema, ProbeManifestSchema, RemediationSchema, Severity } from "@perimeter/sdk";

export const ISOLATED_PROTOCOL_VERSION = 1;
export const MAX_WORKER_FRAME_BYTES = 256 * 1024;
export const MAX_WORKER_OUTPUT_BYTES = 8 * 1024 * 1024;

export const IsolatedProbeSchema = z.object({
  manifest: ProbeManifestSchema.refine((manifest) => manifest.safety.class === "read-only" && !manifest.safety.destructive,
    "Isolated protocol v1 supports read-only probes only"),
  timeoutSeconds: z.number().int().min(1).max(3600).default(60),
  runner: z.discriminatedUnion("kind", [
    z.object({
      kind: z.literal("container"),
      /** Docker-compatible executable; the operator trusts this runtime. */
      runtime: z.string().min(1).default("docker"),
      image: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$/),
      command: z.array(z.string()).default([]),
    }).strict(),
    z.object({
      kind: z.literal("command"),
      command: z.array(z.string().min(1)).min(1),
      /** Custom launchers/local processes own their security boundary. No sandbox is implied. */
      acknowledgeExternalSecurity: z.literal(true),
    }).strict(),
  ]),
}).strict();
export type IsolatedProbeConfig = z.infer<typeof IsolatedProbeSchema>;

export const WorkerMessageSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("grpc-request"), id: z.number().int().nonnegative(), request: GrpcRequestSchema }).strict(),
  z.object({
    type: z.literal("request"), id: z.number().int().nonnegative(),
    request: z.object({
      method: z.enum(["GET", "HEAD", "OPTIONS"]), url: z.string().min(1).max(8192),
      as: z.string().optional(),
      jwtVariant: z.enum(["none-alg", "signature-stripped", "tenant-swapped", "expired"]).optional(),
      headers: z.record(z.string().max(8192)).refine((headers) => Object.keys(headers).length <= 64).optional(),
    }).strict(),
  }).strict(),
  z.object({
    type: z.literal("finding"), endpointId: z.string(), locator: z.string().min(1).max(256),
    title: z.string().max(4096), severity: Severity, confidence: Confidence,
    summary: z.string().max(16384), exchangeRefs: z.array(z.string()).min(1).max(50),
    remediation: RemediationSchema,
  }).strict(),
  z.object({ type: z.literal("pass"), endpointId: z.string(), title: z.string().max(4096), summary: z.string().max(16384) }).strict(),
  z.object({ type: z.literal("done"), version: z.literal(ISOLATED_PROTOCOL_VERSION) }).strict(),
]);
