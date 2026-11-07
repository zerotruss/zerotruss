# Signing and checking the boundary file with Ed25519; a signature covers the exact bytes of the file
import base64
import hashlib

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# Put in front of the data before signing, so a signature made here cannot be reused for anything else
PREFIX = b"zerotruss boundary v1\n"


# What is actually signed: the fixed prefix followed by the exact bytes of the file
def signed_message(data):
    return PREFIX + data


# A new private key, as 32 raw bytes
def new_private_key():
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


# The public key for a private key (32 raw bytes), as PEM text in bytes
def public_key_pem(private_bytes):
    public = Ed25519PrivateKey.from_private_bytes(private_bytes).public_key()
    return public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


# Read a public key from PEM bytes; ValueError if it is not an Ed25519 public key
def load_public_key(public_pem):
    try:
        key = serialization.load_pem_public_key(public_pem)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError("the public key file is not a valid public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("the public key is not an Ed25519 key")
    return key


# A short fingerprint of a public key, for people to compare: 16 hex characters
def fingerprint(public_pem):
    raw = load_public_key(public_pem).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


# Sign the data; the signature is returned as one line of base64 text
def sign(private_bytes, data):
    key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return base64.b64encode(key.sign(signed_message(data))).decode()


# Check a signature; returns None if it is valid, otherwise raises ValueError saying why not
def verify(public_pem, signature_text, data):
    key = load_public_key(public_pem)
    try:
        signature = base64.b64decode(signature_text.strip(), validate=True)
    except ValueError:
        raise ValueError("the signature file is not valid base64 text") from None
    try:
        key.verify(signature, signed_message(data))
    except InvalidSignature:
        raise ValueError("the signature does not match the boundary file and public key") from None
