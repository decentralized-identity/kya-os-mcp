"""Digests as the protocol writes them: `sha256:` and the 64 lowercase hex digits of a SHA-256.

A domain digest is the construction the audit protocol and SPEC.md 7.8 share: the SHA-256 of a
domain, a 0x00 byte and a value's RFC 8785 (JCS) bytes. A caller passes the domain with its 0x00.
"""

import hashlib
import re

from strict_json import jcs

DIGEST_FORM = re.compile(r"sha256:[0-9a-f]{64}")


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def domain_digest(domain: bytes, value) -> str:
    return sha256_digest(domain + jcs(value))
