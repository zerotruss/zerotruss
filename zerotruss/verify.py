# Chain validator: python -m zerotruss.verify chain.jsonl [--strict]; reports anything wrong with the log
import hashlib  # standard library only: shares no code with the log writer, so its mistakes cannot hide here
import json
import re
import sys

ZERO_HASH = "0" * 64

# Every record must carry these fields (the hash fields are checked separately).
REQUIRED_FIELDS = ("seq", "ts", "kind", "tool", "decision", "reason", "tool_use_id", "call_id",
                   "trace_id", "prev_hash")

# A line looks like: {"record":<body>,"hash":"<hash>"}
LINE_START = '{"record":'
HASH_MARKER = ',"hash":"'
LINE_END = '"}'

HEX64 = re.compile(r"[0-9a-f]{64}")


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# A string field, or "" if it is missing or not a string
def text_of(record, key):
    value = record.get(key)
    return value if isinstance(value, str) else ""


# Split one line into its number, stored hash, exact record text and record; ValueError says what is wrong
def parse_line(number, text):
    if not text.startswith(LINE_START):
        raise ValueError('line does not start with {"record":')
    rest = text[len(LINE_START):]
    split = rest.rfind(HASH_MARKER)
    if split == -1:
        raise ValueError('no "hash" field found')
    body = rest[:split]  # the hash covers this exact text
    stored_hash = rest[split + len(HASH_MARKER):]
    if not stored_hash.endswith(LINE_END):
        raise ValueError('line is cut off: it does not end with "}')
    try:
        record = json.loads(body)
    except (ValueError, RecursionError) as error:
        raise ValueError(f"record is not valid JSON: {error}") from None
    if not isinstance(record, dict):
        raise ValueError("record is not a JSON object")
    return {"number": number, "hash": stored_hash[:-len(LINE_END)], "body": body, "record": record}


# ---------- per-line checks ----------

# The stored hash must equal the SHA-256 of the record text
def check_hash(line, findings):
    if sha256(line["body"]) != line["hash"]:
        findings.append((line["number"], "error", "hash mismatch: the record was changed after it was written"))


# prev_hash must equal the previous line's hash; a zero one mid-file starts a new segment (returns True then)
def check_link(line, previous_hash, findings):
    prev_hash = text_of(line["record"], "prev_hash")
    number = line["number"]
    if previous_hash is None:
        if prev_hash != ZERO_HASH:
            findings.append((number, "error", "first record does not start from the zero hash"))
        return True
    if prev_hash == ZERO_HASH:
        findings.append((number, "warning", "chain restart: a new segment begins here"))
        return True
    if prev_hash != previous_hash:
        findings.append((number, "error", "broken link: prev_hash is not the previous line's hash"))
    return False


# The seq as a whole number, or None if it is missing or not one (a bool is not one)
def seq_of(record):
    seq = record.get("seq")
    if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0:
        return seq
    return None


# seq must go up by exactly 1, and start at 1 in each segment
def check_seq(line, expected, findings):
    seq = seq_of(line["record"])
    if seq is None:
        findings.append((line["number"], "error", "seq is missing or not a number"))
    elif seq != expected:
        findings.append((line["number"], "error", f"seq is {seq}, expected {expected}"))


# Required fields, known kind and decision, and the right hash field for the kind
def check_shape(line, findings):
    record, number = line["record"], line["number"]
    for field in REQUIRED_FIELDS:
        if field not in record:
            findings.append((number, "error", f"missing field: {field}"))
            return

    kind, decision = text_of(record, "kind"), text_of(record, "decision")
    if kind == "request":
        allowed_decisions = ("allow", "deny")
    elif kind == "response":
        allowed_decisions = ("success", "tool_error", "deny")
    else:
        findings.append((number, "error", f"unknown kind: {record['kind']!r}"))
        return
    if decision not in allowed_decisions:
        findings.append((number, "error", f"decision {decision!r} is not valid for a {kind}"))

    # A request carries args_hash, a response carries result_hash, never both.
    wanted, unwanted = ("args_hash", "result_hash") if kind == "request" else ("result_hash", "args_hash")
    if unwanted in record:
        findings.append((number, "error", f"{unwanted} on a {kind}"))
    if not HEX64.fullmatch(text_of(record, wanted)):
        findings.append((number, "error", f"{wanted} is missing or not 64 hex characters"))


# ---------- per-call checks ----------

# First 8 characters of a call_id, enough to recognise it in a message
def short(call_id):
    return call_id[:8]


# Group the records by call_id and check each call on its own
def check_pairs(entries, findings):
    calls = {}
    for entry in entries:
        if entry["call_id"] == "":
            findings.append((entry["number"], "error",
                             f"empty call_id on a {entry['kind']}: this call cannot be paired"))
        else:
            calls.setdefault(entry["call_id"], []).append(entry)
    for call_id, records in calls.items():
        check_call(call_id, records, findings)


# One call should be exactly one request followed by one response
def check_call(call_id, records, findings):
    ident = short(call_id)
    requests = [r for r in records if r["kind"] == "request"]
    responses = [r for r in records if r["kind"] == "response"]

    for extra in requests[1:]:
        findings.append((extra["number"], "error", f"call {ident} has more than one request"))
    for extra in responses[1:]:
        findings.append((extra["number"], "error", f"call {ident} has more than one response"))

    request = requests[0] if requests else None
    response = responses[0] if responses else None
    if request is None and response is not None:
        findings.append((response["number"], "error", f"response without a request (call {ident})"))
    elif request is not None and response is None:
        # A denied request never reaches the tool, so no response is fine; an allowed one may lack it if upstream failed
        if request["decision"] == "allow":
            findings.append((request["number"], "warning", f"allowed request has no response (call {ident})"))
    elif request is not None and response is not None:
        if response["number"] < request["number"]:
            findings.append((response["number"], "error", f"response comes before its request (call {ident})"))
        if request["decision"] == "deny":
            findings.append((response["number"], "error",
                             f"response to a denied request: the tool ran (call {ident})"))
        # An empty trace_id is normal (the gateway may leave it out); only a clash is odd.
        if request["trace_id"] and response["trace_id"] and request["trace_id"] != response["trace_id"]:
            findings.append((response["number"], "warning",
                             f"trace_id differs between request and response (call {ident})"))


# ---------- the whole file ----------

# Check the whole log text; errors mean it cannot be trusted, warnings are odd but innocent (e.g. a restart)
def check_chain(text):
    findings, denies, entries = [], [], []  # a finding is (line number, "error" or "warning", message)
    records = segments = 0
    previous_hash = None
    last_seq = 0

    lines = text.split("\n")  # not splitlines(): a record may hold characters that splitlines splits on
    if lines[-1] == "":
        lines.pop()

    for number, text_line in enumerate(lines, start=1):
        try:
            line = parse_line(number, text_line)
        except ValueError as error:
            findings.append((number, "error", str(error)))
            continue
        records += 1
        record = line["record"]

        check_hash(line, findings)
        if check_link(line, previous_hash, findings):
            segments += 1
            last_seq = 0
        check_seq(line, last_seq + 1, findings)
        check_shape(line, findings)

        if text_of(record, "decision") == "deny":
            denies.append((number, text_of(record, "kind"), text_of(record, "reason")))
        entries.append({
            "number": number,
            "kind": text_of(record, "kind"),
            "decision": text_of(record, "decision"),
            "call_id": text_of(record, "call_id"),
            "trace_id": text_of(record, "trace_id"),
        })

        seq = seq_of(record)
        last_seq = seq if seq is not None else last_seq + 1
        previous_hash = line["hash"]

    # Every record is written with a newline after it, so a missing one means a torn write.
    if text and not text.endswith("\n"):
        findings.append((len(lines), "error", "file does not end with a newline: the last write may be cut off"))

    check_pairs(entries, findings)
    findings.sort(key=lambda finding: finding[0])  # stable: keeps the order within a line
    return {"findings": findings, "denies": denies, "records": records, "segments": segments}


# Exit code: 0 if fine, 1 if errors (or warnings with --strict), 2 if the file could not be read
def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    strict = "--strict" in args
    paths = [arg for arg in args if not arg.startswith("--")]
    if not paths:
        print("usage: python -m zerotruss.verify chain.jsonl [--strict]", file=sys.stderr)
        return 2
    try:
        with open(paths[0], encoding="utf-8", newline="") as file:
            text = file.read()
    except (OSError, UnicodeDecodeError) as error:
        print(f"cannot read {paths[0]}: {error}", file=sys.stderr)
        return 2

    report = check_chain(text)
    for number, severity, message in report["findings"]:
        label = "ERROR  " if severity == "error" else "WARNING"
        print(f"line {number}: {label} {message}")
    errors = sum(1 for _, severity, _ in report["findings"] if severity == "error")
    warnings = len(report["findings"]) - errors
    print(f"{report['records']} records, {report['segments']} segment(s), {errors} error(s), "
          f"{warnings} warning(s), {len(report['denies'])} deny record(s)")
    for number, kind, reason in report["denies"]:
        print(f"  line {number}: {kind} denied: {reason}")
    print("Checks internal consistency only; cannot see a rebuilt chain, a cut tail or unlogged calls.")

    return 1 if errors or (strict and warnings) else 0


if __name__ == "__main__":
    sys.exit(main())
