import { z } from "zod";
import type { HttpExchange } from "./finding.js";

/** Probes select reviewed calls, never a host, method, proto or arbitrary payload. */
export const GrpcRequestSchema = z.object({
  endpointId: z.string().min(1),
  as: z.string().optional(),
  scratchObjectId: z.string().min(1).max(256).optional(),
}).strict();
export type GrpcRequest = z.infer<typeof GrpcRequestSchema>;
export interface GrpcResponse {
  /** Native gRPC status, not an HTTP status. */
  code: number;
  /** Complete decoded JSON when capture permits; credentials are redacted. */
  exchange: HttpExchange;
}
export interface GuardedGrpcClient {
  request(request: GrpcRequest, signal?: AbortSignal): Promise<GrpcResponse>;
}
