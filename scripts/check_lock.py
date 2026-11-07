"""Check the lock files: every locked version must be at least 14 days old and not yanked.

Run:  .venv/bin/python scripts/check_lock.py
Reads requirements.txt and requirements-dev.txt, asks PyPI about each pinned version,
prints one line per package and exits 1 if any version is too new or yanked.
Standard library only, so it adds no dependency.
"""
import datetime
import json
import re
import sys
import urllib.request

MIN_AGE_DAYS = 14
LOCK_FILES = ["requirements.txt", "requirements-dev.txt", "requirements-sbom.txt"]


def pinned_versions(path):
    """The (name, version) pairs written as `name==version` in a lock file."""
    pins = []
    for line in open(path):
        match = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\]+)", line)
        if match:
            pins.append((match.group(1), match.group(2)))
    return pins


def newest_upload(name, version):
    """When the newest file of this version was uploaded, and whether any file is yanked."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        files = json.load(response)["urls"]
    uploaded = max(datetime.datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files)
    return uploaded, any(f.get("yanked") for f in files)


def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    problems = 0
    for lock_file in LOCK_FILES:
        for name, version in pinned_versions(lock_file):
            uploaded, yanked = newest_upload(name, version)
            age = (now - uploaded).days
            bad = yanked or age < MIN_AGE_DAYS
            problems += bad
            note = "YANKED" if yanked else ("TOO NEW" if age < MIN_AGE_DAYS else "ok")
            print(f"{note:8} {name}=={version}  ({age} days old)  [{lock_file}]")
    print(f"{problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
