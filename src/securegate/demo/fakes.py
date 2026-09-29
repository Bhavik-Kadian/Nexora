"""Fake secrets and decoys, built at runtime in real-world formats.

Nothing here is a real secret, and no key-shaped string is written in this file: every value
is assembled from a short prefix and characters drawn from a seeded random generator, so the
same seed always gives the same values. Markers such as PEM headers are assembled from parts.
"""

import base64
import random
import string
import uuid
from dataclasses import dataclass, field
from pathlib import PurePosixPath

SECRET_KINDS = (
    "aws_key_pair",
    "stripe_live",
    "github_pat",
    "acme_token",
    "private_key_block",
    "db_url_password",
    "generic_password",
)
DECOY_KINDS = (
    "placeholder",
    "aws_docs_example",
    "uuid",
    "git_sha",
    "base64_image",
    "minified_js",
    "lockfile_integrity",
    "test_fixture_key",
)
KINDS = SECRET_KINDS + DECOY_KINDS
PLACEHOLDER_VARIANTS = ("your_here", "changeme", "xxxx", "dummy")

# Variable names used when a catalog item gives none. aws_* kinds use it as a prefix.
DEFAULT_NAMES = {
    "aws_key_pair": "AWS",
    "stripe_live": "STRIPE_SECRET_KEY",
    "github_pat": "GITHUB_TOKEN",
    "acme_token": "ACME_PAY_API_KEY",
    "private_key_block": "DEPLOY_PRIVATE_KEY",
    "db_url_password": "DATABASE_URL",
    "generic_password": "ADMIN_PASSWORD",
    "aws_docs_example": "AWS",
    "uuid": "API_CLIENT_ID",
    "git_sha": "ASSET_CACHE_KEY",
    "base64_image": "LOGO_DATA_URI",
    "lockfile_integrity": "integrity",
    "test_fixture_key": "STRIPE_TEST_KEY",
}
PLACEHOLDER_NAMES = {
    "your_here": "STRIPE_SECRET_KEY",
    "changeme": "POSTGRES_PASSWORD",
    "xxxx": "ACME_PAY_API_KEY",
    "dummy": "GITHUB_TOKEN",
}

# How one "NAME = value" line looks in each kind of file.
ASSIGNMENT = {
    "python": '{name} = "{value}"',
    "yaml": '{name}: "{value}"',
    "js": 'export const {name} = "{value}";',
    "json": '"{name}": "{value}",',
    "env": "{name}={value}",
    "dockerfile": "ENV {name}={value}",
    "shell": 'export {name}="{value}"',
    "markdown": "{name}={value}",
    "raw": "{name}={value}",
}
FILE_TYPES = tuple(ASSIGNMENT)
# Kinds that only make sense in some file types (all others fit everywhere).
ONLY_IN = {
    "private_key_block": ("python", "yaml", "js", "markdown", "raw"),
    "minified_js": ("js",),
    "lockfile_integrity": ("json",),
}

ALNUM = string.ascii_letters + string.digits
BASE32 = string.ascii_uppercase + "234567"
HEX = "0123456789abcdef"
BASE64 = ALNUM + "+/"
SYMBOLS = "!%*+-?@^_~"
DASHES = "-" * 5
PEM_LABEL = "RSA " + "PRIVATE" + " KEY"
RSA_DER_START = bytes.fromhex("308204a40201000282010100")  # how real RSA keys begin
PNG_SIGNATURE = bytes.fromhex("89504e470d0a1a0a")


@dataclass(frozen=True)
class Value:
    """One planted value inside a Plant."""

    offset: int  # line of the Plant where the value starts (0 = first line)
    raw: str = field(repr=False)  # the value as a scanner would read it
    parts: tuple[str, ...] = field(repr=False)  # text that must never appear in any output


@dataclass(frozen=True)
class Plant:
    """The lines to insert into a file for one catalog item."""

    lines: tuple[str, ...]
    values: tuple[Value, ...]


def file_type(path: str) -> str:
    """The kind of file, which decides how a planted line is written."""
    name = PurePosixPath(path).name
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "dockerfile"
    if name == ".env" or name.startswith(".env."):
        return "env"
    suffix = PurePosixPath(path).suffix.lower()
    by_suffix = {
        ".py": "python",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".js": "js",
        ".mjs": "js",
        ".ts": "js",
        ".json": "json",
        ".md": "markdown",
        ".sh": "shell",
    }
    return by_suffix.get(suffix, "raw")


def fits(kind: str, kind_of_file: str) -> bool:
    return kind_of_file in ONLY_IN.get(kind, FILE_TYPES)


def build_plant(
    kind: str,
    kind_of_file: str,
    rng: random.Random,
    *,
    name: str | None = None,
    variant: str | None = None,
) -> Plant:
    """Build the lines for one catalog item, drawing fresh values from `rng`."""
    if kind == "placeholder":
        chosen = variant or "your_here"
        label = name or PLACEHOLDER_NAMES[chosen]
        return _single(kind_of_file, label, _placeholder(chosen, label))
    label = name or DEFAULT_NAMES.get(kind, "")
    match kind:
        case "aws_key_pair":
            key_id = "AKIA" + _draw(rng, BASE32, 16)
            return _pair(kind_of_file, label, key_id, _draw(rng, BASE64, 40))
        case "aws_docs_example":
            return _pair(kind_of_file, label, *_aws_documentation_example())
        case "stripe_live":
            return _single(kind_of_file, label, "sk_" + "live_" + _draw(rng, ALNUM, 24))
        case "test_fixture_key":
            return _single(kind_of_file, label, "sk_" + "test_" + _draw(rng, ALNUM, 24))
        case "github_pat":
            return _single(kind_of_file, label, "gh" + "p_" + _draw(rng, ALNUM, 36))
        case "acme_token":
            return _single(kind_of_file, label, "acme_" + "live_" + _draw(rng, ALNUM, 32))
        case "db_url_password":
            password = _draw(rng, ALNUM, 20)
            url = f"postgresql://demopay_app:{password}@db.demopay.internal:5432/demopay"
            return _single(kind_of_file, label, url, parts=(password,))
        case "generic_password":
            return _single(kind_of_file, label, _password(rng))
        case "private_key_block":
            return _block(kind_of_file, label, _pem_lines(rng))
        case "uuid":
            return _single(kind_of_file, label, str(uuid.UUID(int=rng.getrandbits(128), version=4)))
        case "git_sha":
            return _single(kind_of_file, label, _draw(rng, HEX, 40))
        case "base64_image":
            image = base64.b64encode(PNG_SIGNATURE + rng.randbytes(180)).decode("ascii")
            return _single(kind_of_file, label, "data:image/png;base64," + image)
        case "minified_js":
            line = _minified_js(rng)
            return Plant((line,), (Value(0, line, (line,)),))
        case "lockfile_integrity":
            digest = base64.b64encode(rng.randbytes(64)).decode("ascii")
            return _single(kind_of_file, label, "sha512-" + digest)
    raise ValueError(f"unknown kind {kind!r}")


# --- line layouts ----------------------------------------------------------------------------


def _single(kind_of_file: str, name: str, raw: str, parts: tuple[str, ...] = ()) -> Plant:
    line = ASSIGNMENT[kind_of_file].format(name=name, value=raw)
    return Plant((line,), (Value(0, raw, parts or (raw,)),))


def _pair(kind_of_file: str, prefix: str, key_id: str, secret: str) -> Plant:
    """AWS style: an access key id and a secret access key on two lines."""
    lines = (
        ASSIGNMENT[kind_of_file].format(name=f"{prefix}_ACCESS_KEY_ID", value=key_id),
        ASSIGNMENT[kind_of_file].format(name=f"{prefix}_SECRET_ACCESS_KEY", value=secret),
    )
    return Plant(lines, (Value(0, key_id, (key_id,)), Value(1, secret, (secret,))))


def _block(kind_of_file: str, name: str, block: list[str]) -> Plant:
    """A value that spans many lines, such as a private key."""
    raw = "\n".join(block)
    parts = tuple(block[1:-1])  # the key material; the BEGIN/END markers are not secret
    if kind_of_file == "python":
        return Plant((f'{name} = """', *block, '"""'), (Value(1, raw, parts),))
    if kind_of_file == "js":
        return Plant((f"export const {name} = `", *block, "`;"), (Value(1, raw, parts),))
    if kind_of_file == "yaml":
        return Plant((f"{name}: |", *(f"  {line}" for line in block)), (Value(1, raw, parts),))
    return Plant(tuple(block), (Value(0, raw, parts),))


# --- value builders --------------------------------------------------------------------------


def _draw(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _password(rng: random.Random) -> str:
    """18 characters, like a password manager would make, with at least one symbol."""
    chars = list(_draw(rng, ALNUM + SYMBOLS, 17))
    chars.insert(rng.randrange(len(chars) + 1), rng.choice(SYMBOLS))
    return "".join(chars)


def _pem_lines(rng: random.Random) -> list[str]:
    body = base64.b64encode(RSA_DER_START + rng.randbytes(1180)).decode("ascii")
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return [f"{DASHES}BEGIN {PEM_LABEL}{DASHES}", *lines, f"{DASHES}END {PEM_LABEL}{DASHES}"]


def _placeholder(variant: str, name: str) -> str:
    match variant:
        case "changeme":
            return "changeme"
        case "xxxx":
            return "acme_" + "live_" + "x" * 32
        case "dummy":
            return "dummy_" + name.lower()
    return f"YOUR_{name}_HERE"


def _aws_documentation_example() -> tuple[str, str]:
    """The example key pair printed in AWS documentation, assembled from short chunks."""
    key_id = "".join(("AKIA", "IOSFO", "DNN7E", "XAMPLE"))
    secret = "".join(("wJalr", "XUtnF", "EMI/K", "7MDEN", "G/bPx", "RfiCY", "EXAMP", "LEKEY"))
    return key_id, secret


def _minified_js(rng: random.Random) -> str:
    """One long line of minified JavaScript with hash-like constants, as bundlers produce."""
    helpers = ";".join(
        f"function {_draw(rng, string.ascii_lowercase, 2)}(e,t){{return e[{rng.randrange(9)}]^t}}"
        for _ in range(24)
    )
    build, chunk, key = _draw(rng, HEX, 32), _draw(rng, HEX, 20), _draw(rng, HEX, 16)
    return (
        f'!function(e,t){{"use strict";var n="{build}",r={{chunk:"{chunk}",key:"{key}"}};'
        f"{helpers};e.__demopay=n}}(window,document);"
    )
