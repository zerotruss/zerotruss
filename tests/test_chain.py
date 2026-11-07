"""Unit tests for zerotruss/chain.py."""
import json
import threading

import pytest

from zerotruss.chain import ZERO_HASH, ChainWriter, arguments_hash, sha256_hex

# Two fixed example records with made-up values. Their hashes were computed with the system's shasum
# tool, independently of this code, so they pin down the exact record text and hash format.
EXAMPLE_REQUEST = '{"record":{"seq":1,"ts":"2026-01-01T00:00:00.000000+00:00","kind":"request","tool":"list_directory","args_hash":"d1da4c6d042aaebabb2e15aae3bb039324f2efb9996b58c734ade32172c5dc93","decision":"allow","reason":"inside boundary","tool_use_id":"toolu_example0000000001","call_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000000000000000000000000001","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"},"hash":"fcdc2654a41f28818d6d42b5e1bf16dc3d7bd5fc6c775a237f743731e3028327"}'
EXAMPLE_RESPONSE = '{"record":{"seq":2,"ts":"2026-01-01T00:00:01.000000+00:00","kind":"response","tool":"","result_hash":"8d5706cde045094a27e62ca6e2450d5961a1af1ef704c626199cb1aec16b908f","decision":"success","reason":"","tool_use_id":"","call_id":"00000000-0000-4000-8000-000000000001","trace_id":"00000000000000000000000000000001","prev_hash":"fcdc2654a41f28818d6d42b5e1bf16dc3d7bd5fc6c775a237f743731e3028327"},"hash":"cc2a8d2b1e155651994d7a10d08d3c0ba0fc7ff2a7bb6b1e9255fd2330609b8f"}'


def split_line(line):
    """The record text and the stored hash of one log line."""
    body = line[len('{"record":'):line.rindex(',"hash"')]
    stored_hash = line[line.rindex(',"hash":"') + len(',"hash":"'):-2]
    return body, stored_hash


def read_records(path):
    """Every line of the log as (record dict, body text, stored hash)."""
    result = []
    for line in open(path, encoding="utf-8").read().split("\n")[:-1]:
        body, stored_hash = split_line(line)
        result.append((json.loads(body), body, stored_hash))
    return result


def write_one(writer, kind="request", call_id="c1", **overrides):
    fields = dict(kind=kind, tool="read_text_file", decision="allow", reason="inside boundary",
                  tool_use_id="", call_id=call_id, trace_id="")
    if kind == "request":
        fields["args_hash"] = sha256_hex("args")
    else:
        fields["result_hash"] = sha256_hex("result")
    fields.update(overrides)
    writer.append(**fields)


# ----- hashing -----

def test_a_fixed_example_record_hashes_to_its_stored_hash():
    for line in (EXAMPLE_REQUEST, EXAMPLE_RESPONSE):
        body, stored_hash = split_line(line)
        assert sha256_hex(body) == stored_hash


def test_a_fixed_example_record_is_written_back_as_the_same_text():
    for line in (EXAMPLE_REQUEST, EXAMPLE_RESPONSE):
        body, _ = split_line(line)
        assert json.dumps(json.loads(body), separators=(",", ":"), ensure_ascii=False) == body


def test_sha256_of_text_and_of_the_same_bytes_agree():
    assert sha256_hex("abc") == sha256_hex(b"abc")
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_the_argument_hash_matches_hashes_made_with_an_independent_tool():
    # Expected values computed with the system's shasum on the compact, key-sorted JSON text.
    assert arguments_hash({"path": "/srv/example/data"}) == "d1da4c6d042aaebabb2e15aae3bb039324f2efb9996b58c734ade32172c5dc93"
    assert arguments_hash({"path": "/srv/example"}) == "1e5342db111515145627184a1e08d44c379ffb964dc61fd50bda30301be9aec2"


def test_the_argument_hash_does_not_depend_on_key_order():
    assert arguments_hash({"a": 1, "b": 2}) == arguments_hash({"b": 2, "a": 1})


def test_missing_arguments_hash_as_the_text_null():
    assert arguments_hash(None) == sha256_hex("null")


def test_non_ascii_text_is_hashed_as_written_not_escaped():
    assert arguments_hash({"path": "/é"}) == sha256_hex('{"path":"/é"}')


# ----- the writer -----

def test_the_first_record_starts_the_chain(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    write_one(writer)
    record, body, stored_hash = read_records(tmp_path / "chain.jsonl")[0]
    assert (record["seq"], record["prev_hash"]) == (1, ZERO_HASH)
    assert sha256_hex(body) == stored_hash


def test_each_record_links_to_the_one_before(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    for number in range(4):
        write_one(writer, call_id=f"c{number}")
    records = read_records(tmp_path / "chain.jsonl")
    assert [r["seq"] for r, _, _ in records] == [1, 2, 3, 4]
    for index in range(1, 4):
        assert records[index][0]["prev_hash"] == records[index - 1][2]


def test_fields_are_written_in_the_agreed_order(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    write_one(writer, "request")
    write_one(writer, "response")
    request, response = [r for r, _, _ in read_records(tmp_path / "chain.jsonl")]
    assert list(request) == ["seq", "ts", "kind", "tool", "args_hash", "decision", "reason",
                             "tool_use_id", "call_id", "trace_id", "prev_hash"]
    assert list(response) == ["seq", "ts", "kind", "tool", "result_hash", "decision", "reason",
                              "tool_use_id", "call_id", "trace_id", "prev_hash"]


def test_a_hash_field_that_is_empty_is_left_out(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    write_one(writer, "request", args_hash="")
    record = read_records(tmp_path / "chain.jsonl")[0][0]
    assert "args_hash" not in record and "result_hash" not in record


def test_the_timestamp_is_utc_with_an_offset(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    write_one(writer)
    assert read_records(tmp_path / "chain.jsonl")[0][0]["ts"].endswith("+00:00")


def test_every_line_ends_with_a_newline(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    write_one(writer)
    write_one(writer)
    assert open(tmp_path / "chain.jsonl", encoding="utf-8").read().endswith("}\n")


def test_non_ascii_text_is_stored_as_written_and_hashed_as_written(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    write_one(writer, reason="café ✓")
    record, body, stored_hash = read_records(tmp_path / "chain.jsonl")[0]
    assert "café ✓" in body and record["reason"] == "café ✓"
    assert sha256_hex(body) == stored_hash


def test_a_new_writer_starts_a_new_segment_in_the_same_file(tmp_path):
    path = tmp_path / "chain.jsonl"
    first = ChainWriter(path)
    write_one(first)
    write_one(first)
    first.close()
    second = ChainWriter(path)
    write_one(second)
    records = read_records(path)
    assert [r["seq"] for r, _, _ in records] == [1, 2, 1]
    assert records[2][0]["prev_hash"] == ZERO_HASH


def test_many_threads_still_produce_one_unbroken_chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    writer = ChainWriter(path)

    def work(number):
        for index in range(25):
            write_one(writer, call_id=f"t{number}-{index}")

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    records = read_records(path)
    assert len(records) == 200
    for index, (record, body, stored_hash) in enumerate(records):
        assert record["seq"] == index + 1
        assert sha256_hex(body) == stored_hash
        assert record["prev_hash"] == (ZERO_HASH if index == 0 else records[index - 1][2])


def test_a_failed_write_raises_and_does_not_move_the_chain_on(tmp_path):
    writer = ChainWriter(tmp_path / "chain.jsonl")
    write_one(writer)
    writer.close()  # any later write fails, like a full disk or a removed file would
    with pytest.raises(ValueError):
        write_one(writer)
    assert writer.seq == 1


def test_a_bad_log_path_fails_when_the_writer_is_created(tmp_path):
    with pytest.raises(OSError):
        ChainWriter(tmp_path / "no_such_folder" / "chain.jsonl")
