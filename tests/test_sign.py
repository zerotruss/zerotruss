# Unit tests for zerotruss/sign.py. They use an in-memory keyring, never the real Keychain.
import base64
import json
from pathlib import Path

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import KeyringError

from zerotruss.boundary import load_signed_boundary_file
from zerotruss.sign import ACCOUNT, SERVICE, main
from zerotruss.signing import fingerprint, new_private_key, public_key_pem

BOUNDARY = json.dumps({
    "allowed_tools": ["read_text_file"],
    "allowed_folders": ["/data/test_dir"],
    "expires_at": "2030-01-01T00:00:00Z",
})


# A keyring that keeps everything in memory
class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.items = {}

    def get_password(self, service, username):
        return self.items.get((service, username))

    def set_password(self, service, username, password):
        self.items[(service, username)] = password

    def delete_password(self, service, username):
        self.items.pop((service, username), None)


# Every test gets a fresh in-memory keyring and its own empty folder to work in
@pytest.fixture(autouse=True)
def memory_keyring(tmp_path, monkeypatch):
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    monkeypatch.chdir(tmp_path)
    yield backend
    keyring.set_keyring(previous)


def stored_key(backend):
    return base64.b64decode(backend.items[(SERVICE, ACCOUNT)])


def test_the_tests_never_touch_the_real_keychain():
    assert type(keyring.get_keyring()) is MemoryKeyring


def test_init_puts_the_private_key_in_the_keychain_and_the_public_key_in_a_file(memory_keyring, capsys):
    assert main(["init"]) == 0
    private = stored_key(memory_keyring)
    assert len(private) == 32
    public = Path("boundary.pub").read_bytes()
    assert public == public_key_pem(private)
    assert fingerprint(public) in capsys.readouterr().out


def test_init_does_not_replace_an_existing_key(memory_keyring, capsys):
    main(["init"])
    key, public = stored_key(memory_keyring), Path("boundary.pub").read_bytes()
    assert main(["init"]) == 1
    assert "already exists" in capsys.readouterr().err
    assert stored_key(memory_keyring) == key and Path("boundary.pub").read_bytes() == public


def test_a_signed_boundary_is_accepted_by_the_service_side_loader():
    Path("boundary.json").write_text(BOUNDARY)
    main(["init"])
    assert main(["sign"]) == 0
    boundary = load_signed_boundary_file("boundary.json", "boundary.json.sig", "boundary.pub")
    assert boundary["allowed_tools"] == ["read_text_file"]


def test_an_edit_after_signing_needs_a_new_signature():
    Path("boundary.json").write_text(BOUNDARY)
    main(["init"])
    main(["sign"])
    Path("boundary.json").write_text(BOUNDARY.replace("2030", "2031"))
    with pytest.raises(ValueError, match="does not match"):
        load_signed_boundary_file("boundary.json", "boundary.json.sig", "boundary.pub")
    assert main(["sign"]) == 0
    load_signed_boundary_file("boundary.json", "boundary.json.sig", "boundary.pub")


def test_sign_refuses_a_boundary_the_service_would_refuse(capsys):
    Path("boundary.json").write_text(BOUNDARY.replace("allowed_tools", "allowed_tool"))
    main(["init"])
    capsys.readouterr()
    assert main(["sign"]) == 1
    assert "not signing" in capsys.readouterr().err
    assert not Path("boundary.json.sig").exists()


def test_sign_without_a_boundary_file_fails(capsys):
    main(["init"])
    capsys.readouterr()
    assert main(["sign"]) == 1
    assert "not signing" in capsys.readouterr().err


def test_sign_without_a_key_says_to_run_init(capsys):
    Path("boundary.json").write_text(BOUNDARY)
    assert main(["sign"]) == 1
    assert "init" in capsys.readouterr().err
    assert not Path("boundary.json.sig").exists()


def test_sign_warns_when_the_public_key_file_belongs_to_another_key(capsys):
    Path("boundary.json").write_text(BOUNDARY)
    main(["init"])
    Path("boundary.pub").write_bytes(public_key_pem(new_private_key()))
    capsys.readouterr()
    assert main(["sign"]) == 1
    assert "WARNING" in capsys.readouterr().err
    with pytest.raises(ValueError, match="does not match"):
        load_signed_boundary_file("boundary.json", "boundary.json.sig", "boundary.pub")


def test_sign_warns_when_there_is_no_public_key_file(capsys):
    Path("boundary.json").write_text(BOUNDARY)
    main(["init"])
    Path("boundary.pub").unlink()
    capsys.readouterr()
    assert main(["sign"]) == 1
    assert "WARNING" in capsys.readouterr().err


def test_public_writes_the_public_key_file_again(memory_keyring):
    main(["init"])
    original = Path("boundary.pub").read_bytes()
    Path("boundary.pub").unlink()
    assert main(["public"]) == 0
    assert Path("boundary.pub").read_bytes() == original


def test_public_without_a_key_fails(capsys):
    assert main(["public"]) == 1
    assert "init" in capsys.readouterr().err


def test_the_private_key_is_never_printed_or_written_to_a_file(memory_keyring, capsys):
    Path("boundary.json").write_text(BOUNDARY)
    main(["init"])
    main(["sign"])
    main(["public"])
    output = capsys.readouterr()
    private = stored_key(memory_keyring)
    secrets = [base64.b64encode(private).decode(), private.hex(), base64.urlsafe_b64encode(private).decode()]
    for text in [output.out, output.err] + [path.read_text(errors="replace") for path in Path(".").iterdir()]:
        assert not any(secret in text for secret in secrets)


def test_a_wrong_command_prints_the_usage_and_exits_2(capsys):
    for args in ([], ["bogus"], ["init", "extra"], ["sign", "boundary.json"]):
        assert main(args) == 2
    assert "usage" in capsys.readouterr().err


def test_a_keychain_failure_is_reported_not_raised(memory_keyring, capsys):
    def broken(service, username):
        raise KeyringError("the Keychain is locked")
    memory_keyring.get_password = broken
    assert main(["init"]) == 2
    assert "cannot use the Keychain" in capsys.readouterr().err


def test_a_damaged_stored_key_is_reported_not_used(memory_keyring, capsys):
    for damaged in ["not base64 !!", base64.b64encode(b"short").decode(), base64.b64encode(bytes(33)).decode()]:
        memory_keyring.items[(SERVICE, ACCOUNT)] = damaged
        Path("boundary.json").write_text(BOUNDARY)
        assert main(["sign"]) == 2
        assert "not a valid signing key" in capsys.readouterr().err
