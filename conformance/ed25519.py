"""Ed25519 signatures: the RFC 8032 reference implementation, pure stdlib.

Verification is what the vectors are checked with. Signing is for the cases a verifier is held to
beyond the vectors, which sign what they alter with a key of their own (proof_cases.py), and the
verification equation alone is what those cases show their forgeries under a key of small order
to satisfy.
"""

import hashlib

_p = 2 ** 255 - 19
# The order of the base point (RFC 8032 5.1).
L = 2 ** 252 + 27742317777372353535851937790883648493


def _modp_inv(x):
    return pow(x, _p - 2, _p)


_d = -121665 * _modp_inv(121666) % _p
_modp_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _sha512_modL(s):
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % L


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _point_mul(s, P):
    Q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _p != 0:
        return False
    return True


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _modp_inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _modp_sqrt_m1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_g_y = 4 * _modp_inv(5) % _p
_g_x = _recover_x(_g_y, 0)
_G = (_g_x, _g_y, 1, _g_x * _g_y % _p)


def _point_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def _point_compress(P):
    zinv = _modp_inv(P[2])
    x = P[0] * zinv % _p
    y = P[1] * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("an Ed25519 secret key is 32 bytes")
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key(secret: bytes) -> bytes:
    """The public key of a 32-byte secret key (RFC 8032 5.1.5)."""
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, _G))


def ed25519_sign(secret: bytes, message: bytes) -> bytes:
    """The signature of `message` under a 32-byte secret key (RFC 8032 5.1.6)."""
    a, prefix = _secret_expand(secret)
    A = _point_compress(_point_mul(a, _G))
    r = _sha512_modL(prefix + message)
    Rs = _point_compress(_point_mul(r, _G))
    h = _sha512_modL(Rs + A + message)
    return Rs + int.to_bytes((r + h * a) % L, 32, "little")


_IDENTITY = (0, 1, 1, 0)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature (RFC 8032). Fail-closed on any malformed input.

    A public key of small order is refused, as every Ed25519 path of the TypeScript reference
    refuses it (src/utils/ed25519-public-key.ts): under one, R = identity and S = 0 satisfy the
    verification equation for every message, so anyone could sign as it.
    """
    return (ed25519_equation_holds(public_key, message, signature)
            and not _point_equal(_point_mul(8, _point_decompress(public_key)), _IDENTITY))


def ed25519_equation_holds(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` satisfies the verification equation [S]B = R + [k]A of RFC 8032 5.1.7
    under `public_key`, whatever the key's order: all that a verifier which does not refuse a key
    of small order checks. Fail-closed on any malformed input."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public_key)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= L:
        return False
    h = _sha512_modL(Rs + public_key + message)
    sB = _point_mul(S, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))
