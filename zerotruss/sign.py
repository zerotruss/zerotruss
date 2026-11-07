# The signing command: python -m zerotruss.sign init | sign | public
# The private key lives in the macOS Keychain. The service never needs it, only the public key file.
import base64
import sys
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from zerotruss.boundary import BOUNDARY_FILE, PUBLIC_KEY_FILE, SIGNATURE_FILE, load_boundary
from zerotruss.signing import fingerprint, new_private_key, public_key_pem, sign, verify

SERVICE = "zerotruss"
ACCOUNT = "boundary-signing-key"


# The private key from the Keychain as 32 raw bytes, or None if there is none yet
def read_key():
    stored = keyring.get_password(SERVICE, ACCOUNT)
    if not stored:
        return None
    try:
        key = base64.b64decode(stored, validate=True)
    except ValueError:
        key = b""
    if len(key) != 32:
        raise ValueError("the key stored in the Keychain is not a valid signing key")
    return key


# Save the private key in the Keychain; it is never written to a file or printed
def store_key(private_bytes):
    keyring.set_password(SERVICE, ACCOUNT, base64.b64encode(private_bytes).decode())


# Write boundary.pub from the key in the Keychain (the public key is not secret)
def write_public_key():
    private = read_key()
    if private is None:
        print("there is no signing key in the Keychain yet; run: python -m zerotruss.sign init", file=sys.stderr)
        return 1
    public = public_key_pem(private)
    Path(PUBLIC_KEY_FILE).write_bytes(public)
    print(f"public key written to {PUBLIC_KEY_FILE} (not secret), fingerprint {fingerprint(public)}")
    return 0


# Make a new signing key: the private half goes into the Keychain, the public half into boundary.pub
def init():
    if read_key() is not None:
        print("a signing key already exists in the Keychain; not replacing it", file=sys.stderr)
        return 1
    store_key(new_private_key())
    print(f"signing key created in the Keychain (service {SERVICE!r}, account {ACCOUNT!r})")
    return write_public_key()


# Sign boundary.json; refuses a file the service would refuse, then checks the result against boundary.pub
def sign_boundary():
    try:
        data = Path(BOUNDARY_FILE).read_bytes()
        load_boundary(data.decode("utf-8"))  # never sign a file the service would refuse to load
    except (OSError, ValueError) as error:
        print(f"not signing: {error}", file=sys.stderr)
        return 1
    private = read_key()
    if private is None:
        print("there is no signing key in the Keychain yet; run: python -m zerotruss.sign init", file=sys.stderr)
        return 1
    signature = sign(private, data)
    Path(SIGNATURE_FILE).write_text(signature + "\n")
    print(f"signed {BOUNDARY_FILE}: wrote {SIGNATURE_FILE} (key {fingerprint(public_key_pem(private))})")
    try:
        verify(Path(PUBLIC_KEY_FILE).read_bytes(), signature, data)
    except (OSError, ValueError) as error:
        print(f"WARNING: the service will refuse this signature: {error}", file=sys.stderr)
        return 1
    print(f"checked against {PUBLIC_KEY_FILE}: valid")
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    commands = {"init": init, "sign": sign_boundary, "public": write_public_key}
    if len(args) != 1 or args[0] not in commands:
        print("usage: python -m zerotruss.sign init | sign | public", file=sys.stderr)
        print("  init    make a signing key in the Keychain and write boundary.pub", file=sys.stderr)
        print("  sign    sign boundary.json, writing boundary.json.sig", file=sys.stderr)
        print("  public  write boundary.pub again from the key in the Keychain", file=sys.stderr)
        return 2
    try:
        return commands[args[0]]()
    except KeyringError as error:
        print(f"cannot use the Keychain: {error}", file=sys.stderr)
        return 2
    except ValueError as error:
        print(f"cannot use the signing key: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
