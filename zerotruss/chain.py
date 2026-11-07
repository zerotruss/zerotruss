# The audit log: one line per record, each linked to the one before by a hash (fingerprints only, never contents)
import hashlib
import json
import threading
from datetime import datetime, timezone

ZERO_HASH = "0" * 64


# SHA-256 of text or bytes, as 64 lowercase hex characters
def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# Fingerprint of the arguments: compact JSON with keys sorted (None, a missing value, hashes as "null")
def arguments_hash(arguments):
    text = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_hex(text)


# Appends records to the log one at a time, in order; a failed write raises so the gateway blocks the call
class ChainWriter:

    def __init__(self, path):
        self.file = open(path, "a", encoding="utf-8", newline="\n")  # opened now so a bad path stops startup
        self.lock = threading.Lock()
        self.seq = 0  # every new writer starts a new chain (a segment) in the same file
        self.prev_hash = ZERO_HASH

    # Write one record; args_hash goes on requests, result_hash on responses
    def append(self, kind, tool, decision, reason, tool_use_id, call_id, trace_id,
               args_hash="", result_hash=""):
        with self.lock:
            # The field order matters: the hash covers this exact text.
            record = {
                "seq": self.seq + 1,
                "ts": datetime.now(timezone.utc).isoformat(),
                "kind": kind,
                "tool": tool,
            }
            if args_hash:
                record["args_hash"] = args_hash
            if result_hash:
                record["result_hash"] = result_hash
            record.update(
                decision=decision,
                reason=reason,
                tool_use_id=tool_use_id,
                call_id=call_id,
                trace_id=trace_id,
                prev_hash=self.prev_hash,
            )
            body = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
            record_hash = sha256_hex(body)
            # A line is {"record":<body>,"hash":"<hash>"}; the hash is of the exact body text
            self.file.write('{"record":' + body + ',"hash":"' + record_hash + '"}\n')
            self.file.flush()
            # Only move on once the line is written.
            self.seq += 1
            self.prev_hash = record_hash

    def close(self):
        self.file.close()
