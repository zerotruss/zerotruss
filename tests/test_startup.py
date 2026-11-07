# Tests that start the real service as a process: it must refuse to start without a valid signature
import os
import subprocess
import sys
from pathlib import Path

from zerotruss.signing import new_private_key, public_key_pem, sign

PROJECT = Path(__file__).parent.parent
BOUNDARY = b'{"allowed_tools": ["read_text_file"], "allowed_folders": ["/data/test_dir"], "expires_at": "2030-01-01T00:00:00Z"}\n'


# A folder holding a boundary, its signature and the public key; returns the folder
def make_folder(tmp_path, content=BOUNDARY, private=None):
    private = private or new_private_key()
    (tmp_path / "boundary.json").write_bytes(content)
    (tmp_path / "boundary.json.sig").write_text(sign(private, content) + "\n")
    (tmp_path / "boundary.pub").write_bytes(public_key_pem(private))
    return tmp_path


# Run the service from a folder on a free port; returns the finished process (it only finishes if it refuses to start)
def run_service(folder):
    env = dict(os.environ, PYTHONPATH=str(PROJECT))
    return subprocess.run([sys.executable, "-m", "zerotruss.server", "0"], cwd=folder, env=env,
                          capture_output=True, text=True, timeout=30)


def assert_refused(folder, message):
    result = run_service(folder)
    assert result.returncode == 1, result.stdout + result.stderr
    assert message in result.stderr
    assert not (folder / "chain.jsonl").exists(), "the log must not be opened when the boundary is refused"


def test_it_refuses_to_start_without_a_signature_file(tmp_path):
    folder = make_folder(tmp_path)
    (folder / "boundary.json.sig").unlink()
    assert_refused(folder, "cannot read the signature file")


def test_it_refuses_to_start_without_a_public_key_file(tmp_path):
    folder = make_folder(tmp_path)
    (folder / "boundary.pub").unlink()
    assert_refused(folder, "cannot read the public key file")


def test_it_refuses_to_start_when_the_boundary_was_changed_after_signing(tmp_path):
    folder = make_folder(tmp_path)
    (folder / "boundary.json").write_bytes(BOUNDARY.replace(b"read_text_file", b"write_file"))
    assert_refused(folder, "does not match")


def test_it_refuses_to_start_when_the_signature_is_from_another_key(tmp_path):
    folder = make_folder(tmp_path)
    (folder / "boundary.pub").write_bytes(public_key_pem(new_private_key()))
    assert_refused(folder, "does not match")


def test_it_refuses_to_start_when_the_signed_boundary_is_invalid(tmp_path):
    assert_refused(make_folder(tmp_path, BOUNDARY.replace(b"allowed_tools", b"allowed_tool")), "unknown field")


def test_it_starts_with_a_valid_signature_and_says_which_key_signed(tmp_path):
    folder = make_folder(tmp_path)
    env = dict(os.environ, PYTHONPATH=str(PROJECT))
    process = subprocess.Popen([sys.executable, "-u", "-m", "zerotruss.server", "0"], cwd=folder, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        first = process.stdout.readline()
        second = process.stdout.readline()
    finally:
        process.terminate()
        process.communicate(timeout=10)
    assert "signature verified with key" in first and "tools: 1, folders: 1" in first
    assert "listening on 127.0.0.1" in second
    assert (folder / "chain.jsonl").exists()
