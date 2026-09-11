import protobuf from "protobufjs";
import type { Endpoint } from "@perimeter/sdk";

/** No disk imports, reflection, code generation from remote schemas or streaming. */
export function compileGrpc(endpoint: Endpoint) {
  if (!endpoint.grpc) throw new Error("Missing reviewed gRPC contract");
  try {
    const parsed = protobuf.parse(endpoint.grpc.proto, { keepCase: true });
    if (parsed.imports?.length || parsed.weakImports?.length) throw new Error();
    const root = parsed.root.resolveAll();
    const [service, name] = endpoint.path.slice(1).split("/");
    const method = root.lookupService(service!).methods[name!];
    method?.resolve();
    if (!method || method.requestStream || method.responseStream || !method.resolvedRequestType || !method.resolvedResponseType) throw new Error();
    const requestType = method.resolvedRequestType;
    const responseType = method.resolvedResponseType;
    return {
      requestType, responseType,
      encode(value: Record<string, unknown>): Buffer {
        checkFields(requestType, value, 0);
        const message = requestType.fromObject(value);
        if (requestType.verify(message)) throw new Error("Invalid protobuf request");
        const bytes = Buffer.from(requestType.encode(message).finish());
        if (bytes.length > 16384) throw new Error("gRPC request exceeds 16 KiB");
        return bytes;
      },
      decode(bytes: Buffer): Record<string, unknown> {
        if (bytes.length > 16384) throw new Error("gRPC response exceeds 16 KiB");
        const value = responseType.toObject(responseType.decode(bytes), { longs: String, enums: String, bytes: String, defaults: false }) as Record<string, unknown>;
        if (Buffer.byteLength(JSON.stringify(value)) > 16384) throw new Error("Decoded gRPC response exceeds 16 KiB");
        return value;
      },
    };
  } catch { throw new Error("Invalid reviewed unary gRPC proto/method; bundle imports into the proto text"); }
}

function checkFields(type: protobuf.Type, value: Record<string, unknown>, depth: number): void {
  if (depth > 16 || !value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid protobuf request shape");
  for (const [key, item] of Object.entries(value)) {
    const field = type.fields[key];
    if (!field) throw new Error("Unknown protobuf request field");
    if (field.resolvedType instanceof protobuf.Type && item !== null) {
      const values = field.map ? Object.values(item as Record<string, unknown>) : field.repeated ? item as unknown[] : [item];
      if (!Array.isArray(values)) throw new Error("Invalid repeated protobuf field");
      for (const nested of values) checkFields(field.resolvedType, nested as Record<string, unknown>, depth + 1);
    }
  }
}
