# Unit tests for zerotruss/signing.py
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zerotruss.signing import (
    PREFIX, fingerprint, load_public_key, new_private_key, public_key_pem, sign, verify)

DATA = b'{"allowed_tools": [], "allowed_folders": [], "expires_at": "2030-01-01T00:00:00Z"}\n'


# A fresh key pair: the private key (32 raw bytes) and its public key (PEM)
def make_keys():
    private = new_private_key()
    return private, public_key_pem(private)


def test_a_signature_made_with_the_key_verifies():
    private, public = make_keys()
    assert verify(public, sign(private, DATA), DATA) is None


def test_changing_one_byte_of_the_data_breaks_the_signature():
    private, public = make_keys()
    signature = sign(private, DATA)
    for position in (0, len(DATA) // 2, len(DATA) - 1):
        changed = bytearray(DATA)
        changed[position] ^= 1
        with pytest.raises(ValueError, match="does not match"):
            verify(public, signature, bytes(changed))


def test_adding_or_removing_a_byte_breaks_the_signature():
    private, public = make_keys()
    signature = sign(private, DATA)
    for other in (DATA + b" ", DATA[:-1], b""):
        with pytest.raises(ValueError, match="does not match"):
            verify(public, signature, other)


def test_a_different_key_does_not_verify():
    private, _ = make_keys()
    _, other_public = make_keys()
    with pytest.raises(ValueError, match="does not match"):
        verify(other_public, sign(private, DATA), DATA)


def test_the_signature_is_one_line_of_base64_for_64_bytes():
    private, _ = make_keys()
    signature = sign(private, DATA)
    assert "\n" not in signature
    assert len(base64.b64decode(signature, validate=True)) == 64


def test_the_same_key_and_data_always_give_the_same_signature():
    private, _ = make_keys()
    assert sign(private, DATA) == sign(private, DATA)


def test_the_signature_is_over_the_prefix_and_the_exact_bytes():
    # Checked against the library used directly, so the prefix and nothing else is added.
    private, _ = make_keys()
    expected = Ed25519PrivateKey.from_private_bytes(private).sign(PREFIX + DATA)
    assert sign(private, DATA) == base64.b64encode(expected).decode()


def test_a_signature_made_without_the_prefix_is_rejected():
    private, public = make_keys()
    plain = base64.b64encode(Ed25519PrivateKey.from_private_bytes(private).sign(DATA)).decode()
    with pytest.raises(ValueError, match="does not match"):
        verify(public, plain, DATA)


def test_whitespace_around_the_signature_is_ignored():
    private, public = make_keys()
    signature = sign(private, DATA)
    assert verify(public, "  " + signature + "\n\n", DATA) is None


def test_a_signature_that_is_not_base64_is_rejected():
    _, public = make_keys()
    for text in ["not base64!!", "abc", "####", "a b c d"]:
        with pytest.raises(ValueError, match="base64"):
            verify(public, text, DATA)


def test_an_empty_or_cut_off_signature_is_rejected():
    private, public = make_keys()
    signature = sign(private, DATA)
    for text in ["", "   ", signature[:-4], signature[:40], signature + "AAAA"]:
        with pytest.raises(ValueError):
            verify(public, text, DATA)


def test_empty_data_can_be_signed_and_checked():
    private, public = make_keys()
    assert verify(public, sign(private, b""), b"") is None


def test_a_public_key_that_is_not_pem_is_rejected():
    for text in [b"garbage", b"", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"]:
        with pytest.raises(ValueError, match="not a valid public key"):
            load_public_key(text)


def test_a_public_key_of_another_type_is_rejected():
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = other.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError, match="not an Ed25519 key"):
        load_public_key(pem)


def test_a_private_key_is_32_bytes_and_always_gives_the_same_public_key():
    private, public = make_keys()
    assert len(private) == 32
    assert public_key_pem(private) == public
    assert public.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_two_new_keys_are_different():
    assert new_private_key() != new_private_key()


def test_a_private_key_of_the_wrong_length_is_rejected():
    for private in (b"", b"short", bytes(31), bytes(33)):
        with pytest.raises(ValueError):
            sign(private, DATA)
        with pytest.raises(ValueError):
            public_key_pem(private)


def test_the_fingerprint_is_16_hex_characters_that_differ_between_keys():
    _, first = make_keys()
    _, second = make_keys()
    assert len(fingerprint(first)) == 16 and int(fingerprint(first), 16) >= 0
    assert fingerprint(first) == fingerprint(first)
    assert fingerprint(first) != fingerprint(second)
