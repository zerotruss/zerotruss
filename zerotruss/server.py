# The ExtMCP service: agentgateway asks it before and after every tool call (boundary check, audit log, call ids)
import json
import sys
import uuid
from concurrent import futures
from datetime import datetime, timezone

import grpc
from google.protobuf import struct_pb2
from google.protobuf.json_format import MessageToDict

from zerotruss import ext_mcp_pb2 as pb
from zerotruss.boundary import check, load_boundary_file, summary
from zerotruss.chain import ChainWriter, arguments_hash, sha256_hex

SERVICE_NAME = "agentgateway.dev.ext_mcp.ExtMcp"

PRINT_BODIES = True  # print each call's headers, metadata and body on the terminal (False hides them)


# The client's own label for the call, from the params' "_meta" key ending in /toolUseId (or "")
def tool_use_id_from(params):
    meta = params.get("_meta")
    if isinstance(meta, dict):
        for key, value in meta.items():
            if key.endswith("/toolUseId") and isinstance(value, str):
                return value  # client-controlled: only ever a log label, never used for a decision
    return ""


# Pull (tool, arguments, tool_use_id) out of the JSON-RPC params bytes; a bad body gives ("", None, "")
def read_call(body):
    params = {}
    if body:
        text = body.decode("utf-8", errors="replace")
        try:
            value = json.loads(text)
            json.dumps(value, ensure_ascii=False).encode("utf-8")  # rejects lone surrogates
        except (ValueError, RecursionError):
            value = None
        if isinstance(value, dict):
            params = value["params"] if "params" in value else value
    if not isinstance(params, dict):
        params = {}
    name = params.get("name")
    tool = name if isinstance(name, str) else ""
    return tool, params.get("arguments"), tool_use_id_from(params)


# True if the tool's response says it failed (result.isError, or isError at the top)
def is_tool_error(body):
    try:
        value = json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return False
    if not isinstance(value, dict):
        return False
    result = value.get("result")
    if isinstance(result, dict) and isinstance(result.get("isError"), bool):
        return result["isError"]
    return value.get("isError") is True


# The gateway's trace id (second part of the "traceparent" header) or ""; a cross-check only
def trace_id_from(context):
    parts = dict(context.invocation_metadata()).get("traceparent", "").split("-")
    return parts[1] if len(parts) > 1 else ""


# The call id the gateway echoes back in metadata_context, or "" if absent or not text
def cid_from(metadata_context):
    fields = metadata_context.fields
    if "cid" in fields and fields["cid"].HasField("string_value"):
        return fields["cid"].string_value
    return ""


def deny_request(reason):
    return pb.McpRequestResult(
        error=pb.AuthorizationError(code=pb.AuthorizationError.INVALID, reason=reason))


# Print what the gateway sent: gRPC headers, metadata_context, method and body (label is REQ or RESP)
def show_incoming(label, request, context, body):
    if not PRINT_BODIES:
        return
    print(f"{label} GRPC META {dict(context.invocation_metadata())}", flush=True)
    print(f"{label} METADATA_CONTEXT {MessageToDict(request.metadata_context)}", flush=True)
    print(f"{label} method={request.method} body={body.decode('utf-8', errors='replace')}", flush=True)


# The decision on one line: kind, tool, decision, reason and call id
def show(kind, tool, decision, reason, call_id):
    print(f"{kind:8} {tool or '-':26} {decision:10} {reason} call_id={call_id}", flush=True)


# The two calls the gateway makes: one before the tool runs, one after
class Hooks:

    def __init__(self, writer, boundary):
        self.writer = writer
        self.boundary = boundary

    def check_request(self, request, context):
        show_incoming("REQ", request, context, request.mcp_request)
        tool, arguments, tool_use_id = read_call(request.mcp_request)
        # Made here, never taken from the client. The gateway hands it back with the response.
        call_id = str(uuid.uuid4())

        # The first rule broken wins.
        if not request.HasField("metadata_context"):
            # Without the gateway's metadata block we cannot pair the response, so refuse before the tool runs
            reason = "metadata_context missing: gateway is not round-tripping call_id"
        else:
            reason = check(self.boundary, tool, arguments, datetime.now(timezone.utc)) or ""
        decision = "deny" if reason else "allow"

        self.writer.append(
            kind="request", tool=tool, decision=decision, reason=reason or "inside boundary",
            tool_use_id=tool_use_id, call_id=call_id, trace_id=trace_id_from(context),
            args_hash=arguments_hash(arguments))
        show("REQ", tool, decision, reason or "inside boundary", call_id)

        if reason:
            return deny_request(reason)
        metadata = struct_pb2.Struct()
        metadata["cid"] = call_id
        return pb.McpRequestResult(metadata=metadata, **{"pass": pb.Pass()})

    def check_response(self, request, context):
        show_incoming("RESP", request, context, request.mcp_response)
        call_id = cid_from(request.metadata_context)
        result_hash = sha256_hex(request.mcp_response)
        trace_id = trace_id_from(context)

        if call_id == "":
            # The tool already ran, so this can only withhold the result; it is recorded so the gap is visible
            reason = "response without call_id: metadata round-trip failed"
            self.writer.append(
                kind="response", tool="", decision="deny", reason=reason, tool_use_id="",
                call_id="", trace_id=trace_id, result_hash=result_hash)
            show("RESP", "", "deny", reason, call_id)
            return pb.McpResponseResult(
                error=pb.AuthorizationError(code=pb.AuthorizationError.INVALID, reason=reason))

        decision = "tool_error" if is_tool_error(request.mcp_response) else "success"
        self.writer.append(
            kind="response", tool="", decision=decision, reason="", tool_use_id="",
            call_id=call_id, trace_id=trace_id, result_hash=result_hash)
        show("RESP", "", decision, "", call_id)
        return pb.McpResponseResult(**{"pass": pb.Pass()})  # "pass" is a Python keyword


# A gRPC server with the two hooks registered; returns (server, port)
def build_server(hooks, address):
    handlers = grpc.method_handlers_generic_handler(SERVICE_NAME, {
        "CheckRequest": grpc.unary_unary_rpc_method_handler(
            hooks.check_request,
            request_deserializer=pb.McpRequest.FromString,
            response_serializer=pb.McpRequestResult.SerializeToString),
        "CheckResponse": grpc.unary_unary_rpc_method_handler(
            hooks.check_response,
            request_deserializer=pb.McpResponse.FromString,
            response_serializer=pb.McpResponseResult.SerializeToString),
    })
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    server.add_generic_rpc_handlers((handlers,))
    port = server.add_insecure_port(address)
    return server, port


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "9001"
    # Load the boundary first: a missing or invalid file stops the service, so it never allows everything
    try:
        boundary = load_boundary_file("boundary.json")
        writer = ChainWriter("chain.jsonl")  # opened now: a bad path stops the service here too
    except (ValueError, OSError) as error:
        print(f"cannot start: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"boundary loaded ({summary(boundary)})", flush=True)
    server, port = build_server(Hooks(writer, boundary), f"127.0.0.1:{port}")
    server.start()
    print(f"ExtMCP service listening on 127.0.0.1:{port}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
