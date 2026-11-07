"""Unit tests for zerotruss/verify.py."""
import hashlib
import json

from zerotruss.chain import ChainWriter
from zerotruss.verify import ZERO_HASH, check_chain, main

# Two fixed example records with made-up values (a request and its response). Their hashes were computed
# with the system's shasum tool, independently of this code.
EXAMPLE_REQUEST = '{"record":{"seq":1,"ts":"2026-01-01T00:00:00.000000+00:00","kind":"request","tool":"list_directory","args_hash":"d1da4c6d042aaebabb2e15aae3bb039324f2efb9996b58c734ade32172c5dc93","decision":"allow","reason":"inside boundary","tool_use_id":"toolu_example0000000001","call_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000000000000000000000000001","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"},"hash":"fcdc2654a41f28818d6d42b5e1bf16dc3d7bd5fc6c775a237f743731e3028327"}'
EXAMPLE_RESPONSE = '{"record":{"seq":2,"ts":"2026-01-01T00:00:01.000000+00:00","kind":"response","tool":"","result_hash":"8d5706cde045094a27e62ca6e2450d5961a1af1ef704c626199cb1aec16b908f","decision":"success","reason":"","tool_use_id":"","call_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000000000000000000000000001","prev_hash":"fcdc2654a41f28818d6d42b5e1bf16dc3d7bd5fc6c775a237f743731e3028327"},"hash":"cc2a8d2b1e155651994d7a10d08d3c0ba0fc7ff2a7bb6b1e9255fd2330609b8f"}'


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def record_text(seq, prev, kind, decision, call_id, trace_id):
    """A record body in the same field order the log writer uses."""
    record = {"seq": seq, "ts": "2026-01-01T00:00:00+00:00", "kind": kind, "tool": "t"}
    if kind == "request":
        record["args_hash"] = sha("args")
    else:
        record["result_hash"] = sha("result")
    record.update(decision=decision, reason="", tool_use_id="", call_id=call_id,
                  trace_id=trace_id, prev_hash=prev)
    return json.dumps(record, separators=(",", ":"))


def wrap(body):
    """A full log line for a record body, and its hash."""
    record_hash = sha(body)
    return '{"record":' + body + ',"hash":"' + record_hash + '"}', record_hash


def link(count, make):
    """A correctly linked chain of `count` lines; make(i, prev_hash) returns the i-th record body."""
    prev, lines = ZERO_HASH, []
    for i in range(count):
        line, prev = wrap(make(i, prev))
        lines.append(line)
    return lines


def build(specs):
    """Chain from (seq, kind, decision) specs. Call ids pair records 1+2, 3+4, and so on."""
    return link(len(specs), lambda i, prev: record_text(
        specs[i][0], prev, specs[i][1], specs[i][2], f"a{(specs[i][0] + 1) // 2}", ""))


def build_calls(specs):
    """Chain from (kind, decision, call_id, trace_id) specs, with seq 1, 2, 3, ..."""
    return link(len(specs), lambda i, prev: record_text(i + 1, prev, *specs[i]))


def file_text(lines):
    return "".join(line + "\n" for line in lines)


def three_lines():
    return build([(1, "request", "allow"), (2, "response", "success"), (3, "request", "deny")])


def has(report, line, severity, text):
    """True if some finding on `line` has this severity and mentions `text`."""
    return any(f[0] == line and f[1] == severity and text in f[2] for f in report["findings"])


def count(report, severity):
    return sum(1 for finding in report["findings"] if finding[1] == severity)


# ----- per line -----

def test_valid_chain_has_no_findings():
    report = check_chain(file_text(three_lines()))
    assert report["findings"] == []
    assert (report["records"], report["segments"]) == (3, 1)


def test_empty_file_has_no_findings():
    assert check_chain("")["findings"] == []


def test_changed_record_is_a_hash_mismatch():
    lines = three_lines()
    lines[1] = lines[1].replace('"tool":"t"', '"tool":"other"')
    assert has(check_chain(file_text(lines)), 2, "error", "hash mismatch")


def test_deleted_line_breaks_the_link():
    lines = three_lines()
    del lines[1]
    report = check_chain(file_text(lines))
    assert has(report, 2, "error", "broken link")
    assert has(report, 2, "error", "seq is 3, expected 2")


def test_swapped_lines_are_caught():
    lines = three_lines()
    lines[1], lines[2] = lines[2], lines[1]
    assert has(check_chain(file_text(lines)), 2, "error", "broken link")


def test_seq_gap_is_caught_even_when_links_are_valid():
    lines = build([(1, "request", "allow"), (3, "response", "success")])
    assert has(check_chain(file_text(lines)), 2, "error", "seq is 3, expected 2")


def test_cut_off_last_line_is_caught():
    text = file_text(three_lines())[:-40]
    report = check_chain(text)
    assert has(report, 3, "error", "cut off")
    assert has(report, 3, "error", "newline")


def test_missing_final_newline_is_caught():
    text = file_text(three_lines()).rstrip("\n")
    assert has(check_chain(text), 3, "error", "newline")


def test_garbage_line_is_caught():
    lines = three_lines()
    lines[1] = "not json"
    assert has(check_chain(file_text(lines)), 2, "error", "does not start")


def test_first_record_must_start_from_zero():
    line, _ = wrap(record_text(1, sha("x"), "request", "allow", "a1", ""))
    assert has(check_chain(file_text([line])), 1, "error", "zero hash")


def test_restart_is_a_warning_not_an_error():
    # Two runs of the service: each starts from the zero hash, with its own call ids.
    lines = build_calls([("request", "allow", "x", ""), ("response", "success", "x", "")])
    lines += build_calls([("request", "allow", "y", ""), ("response", "success", "y", "")])
    report = check_chain(file_text(lines))
    assert count(report, "error") == 0, report["findings"]
    assert has(report, 3, "warning", "restart")
    assert report["segments"] == 2


def test_unknown_kind_and_bad_decision_are_caught():
    lines = build([(1, "banana", "allow"), (2, "request", "success")])
    report = check_chain(file_text(lines))
    assert has(report, 1, "error", "unknown kind")
    assert has(report, 2, "error", "not valid for a request")


def test_wrong_hash_field_for_the_kind_is_caught():
    # A response carrying args_hash instead of result_hash.
    body = record_text(1, ZERO_HASH, "response", "success", "a1", "").replace("result_hash", "args_hash")
    line, _ = wrap(body)
    report = check_chain(file_text([line]))
    assert has(report, 1, "error", "args_hash on a response")
    assert has(report, 1, "error", "result_hash is missing")


def test_missing_required_field_is_caught():
    body = record_text(1, ZERO_HASH, "request", "allow", "a1", "").replace('"reason":"",', "")
    line, _ = wrap(body)
    assert has(check_chain(file_text([line])), 1, "error", "missing field: reason")


def test_a_hash_with_capital_letters_is_not_accepted():
    body = record_text(1, ZERO_HASH, "request", "allow", "a1", "").replace(sha("args"), sha("args").upper())
    line, _ = wrap(body)
    assert has(check_chain(file_text([line])), 1, "error", "not 64 hex")


def test_a_seq_that_is_not_a_whole_number_is_caught():
    for seq in ("true", "1.5", '"1"', "-1", "null"):
        body = record_text(1, ZERO_HASH, "request", "allow", "a1", "").replace('"seq":1', f'"seq":{seq}')
        line, _ = wrap(body)
        assert has(check_chain(file_text([line])), 1, "error", "seq is"), seq


def test_deny_with_no_response_is_fine():
    lines = build([(1, "request", "deny")])
    assert check_chain(file_text(lines))["findings"] == []


def test_the_fixed_example_records_form_a_valid_chain():
    # Hashed with the system's shasum tool, so this checks the validator against an independent hash.
    report = check_chain(EXAMPLE_REQUEST + "\n" + EXAMPLE_RESPONSE + "\n")
    assert report["findings"] == []
    assert (report["records"], report["segments"]) == (2, 1)


def test_a_character_python_would_split_lines_on_does_not_split_a_record():
    # U+2028 is allowed inside a JSON string; str.splitlines() would cut the line there.
    body = record_text(1, ZERO_HASH, "request", "deny", "a1", "").replace('"tool":"t"', '"tool":"a b"')
    line, _ = wrap(body)
    assert check_chain(file_text([line]))["findings"] == []


# ----- per call -----

def test_request_and_response_with_the_same_call_id_are_clean():
    lines = build_calls([("request", "allow", "x", ""), ("response", "success", "x", "")])
    assert check_chain(file_text(lines))["findings"] == []


def test_tool_error_response_is_fine():
    lines = build_calls([("request", "allow", "x", ""), ("response", "tool_error", "x", "")])
    assert check_chain(file_text(lines))["findings"] == []


def test_allowed_request_without_response_is_a_warning():
    report = check_chain(file_text(build_calls([("request", "allow", "x", "")])))
    assert count(report, "error") == 0
    assert has(report, 1, "warning", "no response")


def test_response_without_request_is_an_error():
    report = check_chain(file_text(build_calls([("response", "success", "x", "")])))
    assert has(report, 1, "error", "response without a request")


def test_response_before_request_is_an_error():
    lines = build_calls([("response", "success", "x", ""), ("request", "allow", "x", "")])
    assert has(check_chain(file_text(lines)), 1, "error", "comes before its request")


def test_response_to_a_denied_request_is_an_error():
    lines = build_calls([("request", "deny", "x", ""), ("response", "success", "x", "")])
    assert has(check_chain(file_text(lines)), 2, "error", "the tool ran")


def test_repeated_call_id_is_an_error():
    lines = build_calls([
        ("request", "allow", "x", ""), ("response", "success", "x", ""),
        ("request", "allow", "x", ""), ("response", "success", "x", ""),
    ])
    report = check_chain(file_text(lines))
    assert has(report, 3, "error", "more than one request")
    assert has(report, 4, "error", "more than one response")


def test_empty_call_id_is_an_error_even_for_a_deny():
    report = check_chain(file_text(build_calls([("response", "deny", "", "")])))
    assert has(report, 1, "error", "empty call_id")


def test_different_trace_ids_are_a_warning():
    lines = build_calls([("request", "allow", "x", "t1"), ("response", "success", "x", "t2")])
    report = check_chain(file_text(lines))
    assert count(report, "error") == 0
    assert has(report, 2, "warning", "trace_id differs")


def test_empty_trace_id_is_never_flagged():
    lines = build_calls([("request", "allow", "x", "t1"), ("response", "success", "x", "")])
    assert check_chain(file_text(lines))["findings"] == []


def test_denies_are_listed_with_their_line_and_kind():
    lines = build_calls([("request", "allow", "x", ""), ("response", "success", "x", ""), ("request", "deny", "y", "")])
    assert check_chain(file_text(lines))["denies"] == [(3, "request", "")]


# ----- a log written by the real writer, and the command line -----

def test_a_log_written_by_the_real_writer_passes(tmp_path):
    path = tmp_path / "chain.jsonl"
    writer = ChainWriter(path)
    writer.append(kind="request", tool="read_text_file", decision="allow", reason="inside boundary",
                  tool_use_id="toolu_1", call_id="c1", trace_id="t1", args_hash=sha("args"))
    writer.append(kind="response", tool="", decision="success", reason="", tool_use_id="",
                  call_id="c1", trace_id="t1", result_hash=sha("result"))
    writer.append(kind="request", tool="write_file", decision="deny", reason="tool not allowed: write_file",
                  tool_use_id="", call_id="c2", trace_id="", args_hash=sha("args2"))
    writer.close()
    report = check_chain(path.read_text(encoding="utf-8"))
    assert report["findings"] == []
    assert report["denies"] == [(3, "request", "tool not allowed: write_file")]


def test_a_log_with_non_ascii_text_written_by_the_real_writer_passes(tmp_path):
    path = tmp_path / "chain.jsonl"
    writer = ChainWriter(path)
    writer.append(kind="request", tool="t", decision="deny", reason="café   ✓", tool_use_id="",
                  call_id="c1", trace_id="", args_hash=sha("args"))
    writer.close()
    assert check_chain(path.read_text(encoding="utf-8"))["findings"] == []


def test_the_command_exits_0_for_a_good_log_and_prints_a_summary(tmp_path, capsys):
    path = tmp_path / "chain.jsonl"
    path.write_text(file_text(three_lines()), encoding="utf-8")
    assert main([str(path)]) == 0
    output = capsys.readouterr().out
    assert "3 records, 1 segment(s), 0 error(s), 0 warning(s), 1 deny record(s)" in output
    assert "line 3: request denied:" in output


def test_the_command_exits_1_for_errors(tmp_path, capsys):
    lines = three_lines()
    lines[1] = lines[1].replace('"tool":"t"', '"tool":"other"')
    path = tmp_path / "chain.jsonl"
    path.write_text(file_text(lines), encoding="utf-8")
    assert main([str(path)]) == 1
    assert "line 2: ERROR   hash mismatch" in capsys.readouterr().out


def test_strict_makes_warnings_fail(tmp_path):
    path = tmp_path / "chain.jsonl"
    path.write_text(file_text(build_calls([("request", "allow", "x", "")])), encoding="utf-8")
    assert main([str(path)]) == 0
    assert main([str(path), "--strict"]) == 1


def test_the_command_exits_2_when_it_cannot_read_the_file(tmp_path, capsys):
    assert main([str(tmp_path / "missing.jsonl")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_the_command_exits_2_without_a_file_name(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().err
