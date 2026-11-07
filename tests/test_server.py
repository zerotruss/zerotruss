"""Unit tests for zerotruss/server.py: the two hooks, called directly and over a real gRPC connection."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import grpc
import pytest

from zerotruss import ext_mcp_pb2 as pb
from zerotruss.boundary import load_boundary
from zerotruss.chain import ChainWriter, sha256_hex
from zerotruss.server import (
    SERVICE_NAME, Hooks, build_server, cid_from, is_tool_error, read_call, tool_use_id_from, trace_id_from)

READ_INSIDE = '{"name": "read_text_file", "arguments": {"path": "/data/test_dir/file1.txt"}}'
MISSING_METADATA = "metadata_context missing: gateway is not round-tripping call_id"
NO_CALL_ID = "response without call_id: metadata round-trip failed"


class FakeContext:
    """Stands in for the gRPC context: only the incoming headers are used."""

    def __init__(self, traceparent=None):
        self.headers = (("traceparent", traceparent),) if traceparent else ()

    def invocation_metadata(self):
        return self.headers


def make_hooks(tmp_path, expires_at="2099-01-01T00:00:00Z"):
    """Hooks whose boundary allows two tools inside /data/test_dir. Each call gets its own new
    log file inside tmp_path, so a test can make several without them sharing a log."""
    boundary = load_boundary(json.dumps({
        "allowed_tools": ["read_text_file", "list_directory"],
        "allowed_folders": ["/data/test_dir"],
        "expires_at": expires_at,
    }))
    log_path = Path(tempfile.mkdtemp(dir=tmp_path)) / "chain.jsonl"
    return Hooks(ChainWriter(log_path), boundary), log_path


def read_log(path):
    return [json.loads(line)["record"] for line in path.read_text(encoding="utf-8").split("\n")[:-1]]


def make_request(params, with_metadata=True):
    """A tools/call request. params is the JSON-RPC params text (None = no body at all).
    with_metadata says whether the gateway sent metadata_context (it may be empty but present)."""
    message = pb.McpRequest(method="tools/call")
    if params is not None:
        message.mcp_request = params.encode()
    if with_metadata:
        message.metadata_context.SetInParent()
    return message


def make_response(body, cid="abc"):
    """A tools/call response. cid is the call id the gateway echoes back (None = not sent)."""
    message = pb.McpResponse(method="tools/call", mcp_response=body.encode())
    if cid is not None:
        message.metadata_context.fields["cid"].string_value = cid
    return message


def call(tmp_path, params, with_metadata=True, expires_at="2099-01-01T00:00:00Z"):
    """Send one request through the hook. Returns the answer and the one record it logged."""
    hooks, log_path = make_hooks(tmp_path, expires_at)
    answer = hooks.check_request(make_request(params, with_metadata), FakeContext())
    records = read_log(log_path)
    assert len(records) == 1, "exactly one record per call"
    return answer, records[0]


def assert_denied(answer, record, reason):
    """Denied with this reason: logged as a deny, returned as an error, and no call id handed out."""
    assert answer.WhichOneof("result") == "error"
    assert answer.error.reason == reason
    assert answer.error.code == pb.AuthorizationError.INVALID
    assert (record["kind"], record["decision"]) == ("request", "deny")
    assert record["reason"] == reason
    assert not answer.HasField("metadata"), "a denied call must not hand out a call id"


# ----- the request hook -----

def test_a_call_inside_the_boundary_is_allowed_and_logged(tmp_path):
    answer, record = call(tmp_path, READ_INSIDE)
    assert answer.WhichOneof("result") == "pass"
    assert (record["kind"], record["decision"]) == ("request", "allow")
    assert record["reason"] == "inside boundary"
    assert record["tool"] == "read_text_file"
    assert len(record["args_hash"]) == 64
    # The call id handed to the gateway is the one in the log.
    assert record["call_id"] != ""
    assert answer.metadata.fields["cid"].string_value == record["call_id"]


def test_params_wrapped_in_a_params_key_are_read_too(tmp_path):
    answer, record = call(tmp_path, '{"params": ' + READ_INSIDE + '}')
    assert answer.WhichOneof("result") == "pass"
    assert record["tool"] == "read_text_file"


def test_a_path_outside_the_boundary_is_denied(tmp_path):
    params = '{"name": "read_text_file", "arguments": {"path": "/etc/passwd"}}'
    answer, record = call(tmp_path, params)
    assert_denied(answer, record, "path is outside the allowed folders")
    assert record["tool"] == "read_text_file"


def test_the_path_two_levels_up_is_denied(tmp_path):
    params = '{"name": "list_directory", "arguments": {"path": "/data/test_dir/../.."}}'
    answer, record = call(tmp_path, params)
    assert_denied(answer, record, "path is outside the allowed folders")


def test_a_tool_not_on_the_list_is_denied(tmp_path):
    params = '{"name": "write_file", "arguments": {"path": "/data/test_dir/a", "content": "x"}}'
    answer, record = call(tmp_path, params)
    assert_denied(answer, record, "tool not allowed: write_file")


def test_unreadable_arguments_are_denied(tmp_path):
    params = '{"name": "read_text_file", "arguments": {"path": 5}}'
    answer, record = call(tmp_path, params)
    assert_denied(answer, record, "path is not in a readable shape")


def test_a_body_that_is_not_json_is_denied(tmp_path):
    answer, record = call(tmp_path, "not json")
    assert_denied(answer, record, "tool not allowed: ")
    assert record["tool"] == ""


def test_a_request_with_no_body_is_denied(tmp_path):
    answer, record = call(tmp_path, None)
    assert_denied(answer, record, "tool not allowed: ")


def test_an_expired_boundary_denies_even_a_good_call(tmp_path):
    answer, record = call(tmp_path, READ_INSIDE, expires_at="2000-01-01T00:00:00Z")
    assert_denied(answer, record, "boundary expired")


def test_missing_metadata_is_denied_first(tmp_path):
    # A good call is still denied without metadata_context...
    answer, record = call(tmp_path, READ_INSIDE, with_metadata=False)
    assert_denied(answer, record, MISSING_METADATA)
    # ...and so is a call that would also break the boundary: this reason comes first.
    outside = '{"name": "write_file", "arguments": {"path": "/etc/passwd"}}'
    answer, record = call(tmp_path, outside, with_metadata=False)
    assert_denied(answer, record, MISSING_METADATA)


def test_every_call_gets_its_own_call_id(tmp_path):
    hooks, log_path = make_hooks(tmp_path)
    for _ in range(2):
        hooks.check_request(make_request(READ_INSIDE), FakeContext())
    first, second = read_log(log_path)
    assert first["call_id"] != second["call_id"]


def test_a_denied_call_logs_a_hash_of_the_arguments_and_never_the_path(tmp_path):
    params = '{"name": "read_text_file", "arguments": {"path": "/etc/passwd"}}'
    answer, record = call(tmp_path, params)
    assert record["args_hash"] == sha256_hex('{"path":"/etc/passwd"}')
    assert "passwd" not in answer.error.reason and "passwd" not in record["reason"]


def test_the_clients_tool_use_id_is_logged_as_a_label(tmp_path):
    params = ('{"name": "read_text_file", "arguments": {"path": "/data/test_dir/a"}, '
              '"_meta": {"someclient/toolUseId": "toolu_123"}}')
    answer, record = call(tmp_path, params)
    assert answer.WhichOneof("result") == "pass"
    assert record["tool_use_id"] == "toolu_123"


def test_the_gateways_trace_id_is_logged_as_a_cross_check(tmp_path):
    hooks, log_path = make_hooks(tmp_path)
    hooks.check_request(make_request(READ_INSIDE), FakeContext("00-abc123-def456-01"))
    assert read_log(log_path)[0]["trace_id"] == "abc123"


# ----- the response hook -----

def test_a_normal_result_is_logged_as_success(tmp_path):
    hooks, log_path = make_hooks(tmp_path)
    body = '{"content": [{"type": "text", "text": "hello"}]}'
    answer = hooks.check_response(make_response(body, cid="call-1"), FakeContext())
    assert answer.WhichOneof("result") == "pass"
    record = read_log(log_path)[0]
    assert (record["kind"], record["decision"], record["reason"]) == ("response", "success", "")
    assert (record["tool"], record["call_id"]) == ("", "call-1")
    assert record["result_hash"] == sha256_hex(body)


def test_a_result_marked_as_an_error_is_logged_as_tool_error(tmp_path):
    for body in ['{"result": {"isError": true}}', '{"isError": true}']:
        hooks, log_path = make_hooks(tmp_path)
        answer = hooks.check_response(make_response(body), FakeContext())
        assert answer.WhichOneof("result") == "pass"
        assert read_log(log_path)[0]["decision"] == "tool_error", body


def test_a_response_without_a_call_id_is_denied_and_recorded(tmp_path):
    hooks, log_path = make_hooks(tmp_path)
    answer = hooks.check_response(make_response('{"content": []}', cid=None), FakeContext())
    assert answer.WhichOneof("result") == "error"
    assert answer.error.reason == NO_CALL_ID
    assert answer.error.code == pb.AuthorizationError.INVALID
    record = read_log(log_path)[0]
    assert (record["kind"], record["decision"], record["reason"]) == ("response", "deny", NO_CALL_ID)
    assert record["call_id"] == "" and len(record["result_hash"]) == 64


def test_a_call_id_that_is_not_text_counts_as_missing(tmp_path):
    hooks, log_path = make_hooks(tmp_path)
    message = pb.McpResponse(method="tools/call", mcp_response=b"{}")
    message.metadata_context.fields["cid"].number_value = 1
    answer = hooks.check_response(message, FakeContext())
    assert answer.error.reason == NO_CALL_ID


def test_cid_is_read_from_metadata_context():
    message = make_response("{}", cid="abc")
    assert cid_from(message.metadata_context) == "abc"


def test_missing_or_wrong_cid_is_empty():
    assert cid_from(pb.McpResponse().metadata_context) == ""
    other = pb.McpResponse()
    other.metadata_context.fields["sid"].string_value = "x"
    assert cid_from(other.metadata_context) == ""
    number = pb.McpResponse()
    number.metadata_context.fields["cid"].number_value = 1
    assert cid_from(number.metadata_context) == ""


def test_reading_cid_does_not_add_it_to_the_message():
    message = pb.McpResponse()
    cid_from(message.metadata_context)
    assert "cid" not in message.metadata_context.fields


# ----- what is printed on the terminal -----

def test_a_request_prints_its_headers_metadata_body_and_decision(tmp_path, capsys):
    hooks, log_path = make_hooks(tmp_path)
    hooks.check_request(make_request(READ_INSIDE), FakeContext("00-abc123-def456-01"))
    output = capsys.readouterr().out
    assert "REQ GRPC META {'traceparent': '00-abc123-def456-01'}" in output
    assert "REQ METADATA_CONTEXT {}" in output
    assert "REQ method=tools/call body=" + READ_INSIDE in output
    call_id = read_log(log_path)[0]["call_id"]
    assert "REQ      read_text_file" in output and "allow" in output and "inside boundary" in output
    assert f"call_id={call_id}" in output


def test_a_denied_request_prints_the_decision_and_the_reason(tmp_path, capsys):
    hooks, _ = make_hooks(tmp_path)
    outside = '{"name": "read_text_file", "arguments": {"path": "/etc/passwd"}}'
    hooks.check_request(make_request(outside), FakeContext())
    output = capsys.readouterr().out
    assert "REQ method=tools/call body=" + outside in output
    assert "deny" in output and "path is outside the allowed folders" in output


def test_a_response_prints_its_metadata_body_and_decision(tmp_path, capsys):
    hooks, _ = make_hooks(tmp_path)
    hooks.check_response(make_response('{"content": []}', cid="call-1"), FakeContext())
    output = capsys.readouterr().out
    assert "RESP METADATA_CONTEXT {'cid': 'call-1'}" in output
    assert 'RESP method=tools/call body={"content": []}' in output
    assert "RESP     -" in output and "success" in output and "call_id=call-1" in output


def test_the_switch_hides_headers_and_bodies_but_keeps_the_decision(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("zerotruss.server.PRINT_BODIES", False)
    hooks, _ = make_hooks(tmp_path)
    hooks.check_request(make_request(READ_INSIDE), FakeContext("00-abc123-def456-01"))
    hooks.check_response(make_response("{}", cid="call-1"), FakeContext())
    output = capsys.readouterr().out
    assert "GRPC META" not in output and "body=" not in output and "METADATA_CONTEXT" not in output
    assert "allow" in output and "success" in output


# ----- reading a call -----

def test_read_call_finds_tool_arguments_and_label():
    body = b'{"name": "t", "arguments": {"a": 1}, "_meta": {"x/toolUseId": "id-1"}}'
    assert read_call(body) == ("t", {"a": 1}, "id-1")


def test_read_call_gives_empty_values_for_anything_unusable():
    unusable = [
        b"", b"not json", b"[1, 2]", b"5", b"null", b'{"params": null}', b'{"params": [1]}',
        b'{"name": 5}', b"\xff\xfe\xfd", b'{"name": "\\ud800"}', b"[" * 100000,
    ]
    for body in unusable:
        assert read_call(body) == ("", None, ""), body[:20]


def test_read_call_with_invalid_bytes_inside_a_string_still_reads_it():
    tool, _, _ = read_call(b'{"name": "a\xffb"}')
    assert tool == "a�b"


def test_the_tool_use_id_must_be_text_under_a_key_ending_in_tool_use_id():
    assert tool_use_id_from({"_meta": {"a/toolUseId": "x"}}) == "x"
    assert tool_use_id_from({"_meta": {"a/toolUseId": 5}}) == ""
    assert tool_use_id_from({"_meta": {"progressToken": "p"}}) == ""
    assert tool_use_id_from({"_meta": "x"}) == ""
    assert tool_use_id_from({}) == ""


def test_trace_id_is_the_second_part_of_the_header():
    assert trace_id_from(FakeContext("00-abc123-def456-01")) == "abc123"
    assert trace_id_from(FakeContext()) == ""
    assert trace_id_from(FakeContext("garbage")) == ""


def test_is_tool_error_reads_the_error_flag_only_when_it_is_a_real_boolean():
    assert is_tool_error(b'{"result": {"isError": true}}') is True
    assert is_tool_error(b'{"isError": true}') is True
    assert is_tool_error(b'{"result": {"isError": false}}') is False
    assert is_tool_error(b'{"result": {"isError": "yes"}}') is False
    assert is_tool_error(b'{"result": {}}') is False
    assert is_tool_error(b"not json") is False
    assert is_tool_error(b"[1]") is False


# ----- over a real gRPC connection -----

@pytest.fixture
def service(tmp_path):
    hooks, log_path = make_hooks(tmp_path)
    server, port = build_server(hooks, "127.0.0.1:0")
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    yield SimpleNamespace(
        hooks=hooks,
        log_path=log_path,
        channel=channel,
        check_request=channel.unary_unary(
            f"/{SERVICE_NAME}/CheckRequest",
            request_serializer=pb.McpRequest.SerializeToString,
            response_deserializer=pb.McpRequestResult.FromString),
        check_response=channel.unary_unary(
            f"/{SERVICE_NAME}/CheckResponse",
            request_serializer=pb.McpResponse.SerializeToString,
            response_deserializer=pb.McpResponseResult.FromString),
    )
    channel.close()
    server.stop(0)


def test_a_call_is_paired_end_to_end(service):
    headers = (("traceparent", "00-abc123-def456-01"),)
    answer = service.check_request(make_request(READ_INSIDE), metadata=headers)
    assert answer.WhichOneof("result") == "pass"
    cid = answer.metadata.fields["cid"].string_value

    # The gateway echoes the call id back with the response.
    result = service.check_response(make_response('{"content": []}', cid=cid), metadata=headers)
    assert result.WhichOneof("result") == "pass"

    request_record, response_record = read_log(service.log_path)
    assert request_record["call_id"] == response_record["call_id"] == cid
    assert request_record["trace_id"] == response_record["trace_id"] == "abc123"


def test_an_empty_but_present_metadata_context_survives_the_wire(service):
    assert service.check_request(make_request(READ_INSIDE, with_metadata=True)).WhichOneof("result") == "pass"
    denied = service.check_request(make_request(READ_INSIDE, with_metadata=False))
    assert denied.error.reason == MISSING_METADATA


def test_a_request_with_no_call_id_in_the_response_is_denied_over_the_wire(service):
    result = service.check_response(make_response("{}", cid=None))
    assert result.error.reason == NO_CALL_ID


def test_a_failed_log_write_blocks_the_call(service):
    service.hooks.writer.close()  # any write now fails, like a full disk or a removed file would
    with pytest.raises(grpc.RpcError) as error:
        service.check_request(make_request(READ_INSIDE))
    assert error.value.code() == grpc.StatusCode.UNKNOWN  # an error the gateway treats as a block
    with pytest.raises(grpc.RpcError):
        service.check_response(make_response("{}"))


def test_a_method_name_that_is_not_registered_is_unimplemented(service):
    wrong = service.channel.unary_unary(
        f"/{SERVICE_NAME}/NoSuchMethod",
        request_serializer=pb.McpRequest.SerializeToString,
        response_deserializer=pb.McpRequestResult.FromString)
    with pytest.raises(grpc.RpcError) as error:
        wrong(make_request(READ_INSIDE))
    assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED


def test_the_service_name_must_match_the_gateways(service):
    wrong = service.channel.unary_unary(
        "/some.other.Service/CheckRequest",
        request_serializer=pb.McpRequest.SerializeToString,
        response_deserializer=pb.McpRequestResult.FromString)
    with pytest.raises(grpc.RpcError) as error:
        wrong(make_request(READ_INSIDE))
    assert error.value.code() == grpc.StatusCode.UNIMPLEMENTED
