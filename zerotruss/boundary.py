# The boundary: a small JSON file saying what the agent may do (allowed tools, folders, expiry)
import json
import re
from datetime import timezone, datetime

# Argument names that hold file paths. Every tool on the allowed list uses only these.
PATH_KEYS = ("path", "paths", "source", "destination")

FIELDS = ("allowed_tools", "allowed_folders", "expires_at")

# RFC 3339 with a timezone, for example 2030-01-01T00:00:00Z. A date alone is not accepted.
TIME_FORMAT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")


# Split an absolute path into its parts, resolving "." and ".." on the text (None if not absolute)
def split_absolute(path):
    if not path.startswith("/"):
        return None
    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()  # like the OS, ".." at the root stays at the root
        else:
            parts.append(part)
    return parts  # text only: the disk is never looked at, so symlinks are not followed


# Every path in the arguments as (name, path) pairs; any other shape raises ValueError
def path_arguments(arguments):
    if arguments is None:  # no arguments at all
        return []
    if not isinstance(arguments, dict):
        raise ValueError("arguments is not an object")
    found = []
    for key in PATH_KEYS:
        if key not in arguments:
            continue
        value = arguments[key]
        for item in (value if isinstance(value, list) else [value]):  # text or a list of text
            if not isinstance(item, str):  # True, 5 and None are all rejected here
                raise ValueError(f"{key} is not in a readable shape")  # names the argument, not the path
            found.append((key, item))
    return found


# Used by json.loads to refuse NaN and Infinity
def reject_constant(name):
    raise ValueError(f"{name} is not allowed")


# An RFC 3339 date and time with a timezone, as a UTC datetime
def parse_time(value):
    if not isinstance(value, str) or not TIME_FORMAT.fullmatch(value):
        raise ValueError(f"expires_at is not a valid date and time: {value!r}")
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        raise ValueError(f"expires_at is not a valid date and time: {value!r}") from None


# Read the boundary text into a dict (tools, folders as part lists, UTC expiry); ValueError if invalid
def load_boundary(text):
    try:
        data = json.loads(text, parse_constant=reject_constant)
    except (ValueError, RecursionError) as error:
        raise ValueError(f"boundary file is not valid: {error}") from None
    if not isinstance(data, dict):
        raise ValueError("boundary file is not valid: expected a JSON object")
    for field in data:
        if field not in FIELDS:  # unknown fields are rejected so a typo cannot widen the boundary
            raise ValueError(f"boundary file is not valid: unknown field {field!r}")
    for field in FIELDS:
        if field not in data:
            raise ValueError(f"boundary file is not valid: missing field {field!r}")
    for field in ("allowed_tools", "allowed_folders"):
        value = data[field]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"boundary file is not valid: {field} must be a list of text")

    folders = []
    for folder in data["allowed_folders"]:
        parts = split_absolute(folder)
        if parts is None:
            raise ValueError(f"allowed folder is not an absolute path: {folder!r}")
        folders.append(parts)
    return {
        "allowed_tools": data["allowed_tools"],
        "allowed_folders": folders,
        "expires_at": parse_time(data["expires_at"]),
    }


# Read the boundary from a file; an error here should stop the service from starting
def load_boundary_file(path):
    try:
        with open(path, encoding="utf-8") as file:
            text = file.read()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from None
    return load_boundary(text)


# One short line for the startup message
def summary(boundary):
    expires = boundary["expires_at"].strftime("%Y-%m-%dT%H:%M:%SZ")
    return (f"tools: {len(boundary['allowed_tools'])}, "
            f"folders: {len(boundary['allowed_folders'])}, expires: {expires}")


# Returns None if the call is inside the boundary, else the deny reason (now is passed in for tests)
def check(boundary, tool, arguments, now):
    if now >= boundary["expires_at"]:
        return "boundary expired"
    if tool not in boundary["allowed_tools"]:
        return f"tool not allowed: {tool}"
    try:
        found = path_arguments(arguments)
    except ValueError as error:
        return str(error)
    for key, path in found:
        parts = split_absolute(path)
        if parts is None:
            return f"{key} is empty or not an absolute path"
        inside = any(parts[:len(folder)] == folder for folder in boundary["allowed_folders"])
        if not inside:
            return f"{key} is outside the allowed folders"  # names the argument, never the path
    return None
