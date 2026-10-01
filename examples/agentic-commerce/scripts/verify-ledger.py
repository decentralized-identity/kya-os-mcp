#!/usr/bin/env python3
"""Re-verify an exported KYA-OS audit replay bundle with NO SDK — pure stdlib.

"Facts law needs" have to survive the vendor: this script shares no code with
@kya-os/mcp. It re-derives everything the SDK's `verifyAuditBundle` checks for
the structural and cryptographic dimensions, from a bundle.json and the keys
you choose to trust (keys.json: kid → OKP/Ed25519 JWK), and prints a report.

    python3 scripts/verify-ledger.py var/audit/bundle.json --keys var/audit/keys.json
    python3 scripts/verify-ledger.py var/audit/bundle.tampered.json --keys var/audit/keys.json   # exit 1

What it checks, in order:
  manifest    the bundle manifest digest (domain-separated SHA-256 over RFC 8785
              JCS), the exporter's compact JWS (EdDSA) over the canonical core,
              and every component's size + digest against the signed inventory
  entries     per entry: event digest, evidence-manifest digest, entry digest
              (sha256("org.kya-os.audit.entry.v1\\0" ‖ JCS(core))), the recorder
              receipt core rebuilt from the entry, and the receipt's JWS
  chain       genesis at sequence 0, contiguous sequences, previousEntryDigest
              equals the predecessor's entryDigest
  checkpoint  digest + JWS, range (treeSize/first/last/head), and the RFC 9162
              Merkle root recomputed from the entry digests
  inclusion   every inclusion proof re-walked to the checkpoint root
  witness     each observation receipt: scope, digest, JWS by a trusted observer

Exit 0 when every check passes, 1 otherwise. The Ed25519 (RFC 8032 reference
math), JCS and Merkle routines are the same stdlib code used by the example's
receipt verifier and the repository's conformance suite.
"""
import argparse
import base64
import hashlib
import json
import sys

# ── Ed25519 verification (RFC 8032 reference implementation, pure stdlib) ─────────
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _modp_inv(x):
    return pow(x, _p - 2, _p)


_d = -121665 * _modp_inv(121666) % _p
_modp_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _sha512_modL(s):
    return int.from_bytes(hashlib.sha512(s).digest(), "little") % _L


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _point_mul(s, P):
    Q = (0, 1, 1, 0)
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
    x2 = (y * y - 1) * _modp_inv(_d * y * y + 1)
    if x2 == 0:
        if sign:
            return None
        return 0
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


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
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
    if S >= _L:
        return False
    h = _sha512_modL(Rs + public_key + message)
    return _point_equal(_point_mul(S, _G), _point_add(R, _point_mul(h, A)))


# ── RFC 8785 (JCS) ────────────────────────────────────────────────────────────────
def _es_number(value) -> str:
    if isinstance(value, int):
        if abs(value) > 2 ** 53 - 1:
            raise ValueError("unsafe integer outside the admitted JCS space")
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    if value == 0.0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    exp10 = int(exponent) if exponent else 0
    integer_part, _, fraction = mantissa.partition(".")
    if integer_part != "0":
        n = len(integer_part) + exp10
    else:
        n = exp10 - (len(fraction) - len(fraction.lstrip("0")))
    digits = (integer_part + fraction).lstrip("0").rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa_out = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{sign}{mantissa_out}e{'+' if e >= 0 else '-'}{abs(e)}"


def _jcs_serialize(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        return _es_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs_serialize(v) for k, v in items) + "}"
    raise ValueError(f"unsupported JCS value type: {type(value).__name__}")


def jcs(value) -> bytes:
    return _jcs_serialize(value).encode("utf-8")


def sha256_tag(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def domain_digest(domain: str, value) -> str:
    """hashAuditValue: sha256(domain ‖ NUL ‖ JCS(value))."""
    return sha256_tag(domain.encode("utf-8") + b"\x00" + jcs(value))


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── RFC 9162 Merkle tree (leaf = 0x00‖digest, node = 0x01‖left‖right) ─────────────
def digest_bytes(value: str) -> bytes:
    prefix = "sha256:"
    if not isinstance(value, str) or not value.startswith(prefix) or len(value) != len(prefix) + 64:
        raise ValueError("invalid sha256 digest")
    return bytes.fromhex(value[len(prefix):])


def leaf_hash(value: str) -> str:
    return sha256_tag(b"\x00" + digest_bytes(value))


def node_hash(left: str, right: str) -> str:
    return sha256_tag(b"\x01" + digest_bytes(left) + digest_bytes(right))


def merkle_root(leaves) -> str:
    if not leaves:
        return sha256_tag(b"")
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)  # largest power of two < n
    return node_hash(merkle_root(leaves[:split]), merkle_root(leaves[split:]))


def verify_inclusion(leaf: str, index: int, size: int, root: str, path) -> bool:
    if size <= 0 or index < 0 or index >= size:
        return False
    leaf_pos, last_pos = index, size - 1
    calculated = leaf_hash(leaf)
    for sibling in path:
        if last_pos == 0:
            return False
        if leaf_pos & 1 or leaf_pos == last_pos:
            calculated = node_hash(sibling, calculated)
            while leaf_pos != 0 and not leaf_pos & 1:
                leaf_pos //= 2
                last_pos //= 2
        else:
            calculated = node_hash(calculated, sibling)
        leaf_pos //= 2
        last_pos //= 2
    return last_pos == 0 and calculated == root


# ── compact JWS (EdDSA) over exactly these payload bytes ──────────────────────────
def jws_verify(jws: str, payload: bytes, signer: dict, keys: dict) -> tuple[bool, str]:
    try:
        h_b64, p_b64, s_b64 = jws.split(".")
        header = json.loads(b64url_decode(h_b64))
    except Exception as err:  # noqa: BLE001
        return False, f"malformed JWS ({err})"
    if header.get("alg") != signer.get("alg") or signer.get("alg") != "EdDSA":
        return False, f"alg {header.get('alg')} ≠ {signer.get('alg')}"
    if header.get("kid") != signer.get("kid"):
        return False, "kid mismatch"
    if not str(signer.get("kid", "")).startswith(str(signer.get("did", "")) + "#"):
        return False, "kid is not bound to the signer DID"
    jwk = keys.get(signer["kid"])
    if not jwk:
        return False, f"untrusted signer {signer['kid']}"
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False, "trusted key is not OKP/Ed25519"
    if b64url_decode(p_b64) != payload:
        return False, "JWS payload is not the canonical core"
    ok = ed25519_verify(b64url_decode(jwk["x"]), (h_b64 + "." + p_b64).encode("ascii"), b64url_decode(s_b64))
    return ok, "ok" if ok else "signature does not verify"


# ── evidence manifest (mirrors collectAuditEvidenceRefs) ──────────────────────────
def _party_evidence(party):
    return [party["ref"]] if isinstance(party, dict) and party.get("kind") == "evidence_ref" else []


def evidence_manifest(event: dict) -> dict:
    details = event.get("details", {})
    if details.get("family") == "delegation":
        details_evidence = details.get("statusEvidence", [])
    elif details.get("family") == "ledger" and "targetEvidenceRef" in details:
        details_evidence = [details["targetEvidenceRef"]]
    else:
        details_evidence = []
    refs = []
    refs += _party_evidence(event.get("tenantRef"))
    refs += _party_evidence(event.get("source", {}).get("producer"))
    refs += _party_evidence((event.get("session") or {}).get("ref"))
    refs += _party_evidence(event.get("actor"))
    refs += _party_evidence(event.get("responsibleParty"))
    refs += _party_evidence(event.get("resource"))
    if "proof" in event:
        refs.append(event["proof"])
    refs += event.get("evidence", [])
    if "detailRef" in event.get("action", {}):
        refs.append(event["action"]["detailRef"])
    if "detailRef" in (event.get("reason") or {}):
        refs.append(event["reason"]["detailRef"])
    refs += (event.get("authorization") or {}).get("statusEvidence", [])
    refs += details_evidence
    return {"refs": refs}


def receipt_core(core: dict, entry_digest: str) -> dict:
    return {
        "schema": "https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0",
        "ledgerId": core["ledgerId"],
        "ledgerEpochId": core["ledgerEpochId"],
        "sequence": core["sequence"],
        "eventId": core["event"]["eventId"],
        "entryDigest": entry_digest,
        "previousEntryDigest": core["previousEntryDigest"],
        "recordedAt": core["recordedAt"],
        "recorder": core["recorder"],
        "integritySuite": "KYA-AUDIT-JCS-SHA256-JWS-2026",
    }


# ── the verification ──────────────────────────────────────────────────────────────
MEDIA = {
    "entries": "application/vnd.kya-os.audit.entries.v1+json",
    "checkpoints": "application/vnd.kya-os.audit.checkpoints.v1+json",
    "inclusion": "application/vnd.kya-os.audit.inclusion-proofs.v1+json",
    "observations": "application/vnd.kya-os.audit.observations.v1+json",
}


class Report:
    def __init__(self):
        self.sections = {}
        self.ok = True

    def check(self, section: str, name: str, passed: bool, detail: str = ""):
        self.sections.setdefault(section, []).append({"check": name, "ok": bool(passed), **({"detail": detail} if detail else {})})
        if not passed:
            self.ok = False

    def verdicts(self):
        return {s: ("valid" if all(c["ok"] for c in cs) else "invalid") for s, cs in self.sections.items()}


def verify_bundle(bundle: dict, keys: dict) -> Report:
    rep = Report()
    manifest = bundle["manifest"]
    core = manifest["core"]

    # manifest ---------------------------------------------------------------
    rep.check("manifest", "schema", core.get("schema") == "https://schema.kya-os.org/v1/protocol/audit/bundle-manifest/v1.0.0" and core.get("formatVersion") == "1.0.0")
    rep.check("manifest", "integritySuite", core.get("integritySuite") == "KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026")
    rep.check("manifest", "manifestDigest", domain_digest("org.kya-os.audit.bundle-manifest.v1", core) == manifest.get("manifestDigest"))
    ok, why = jws_verify(manifest.get("jws", ""), jcs(core), core.get("exporter", {}), keys)
    rep.check("manifest", "exporter JWS", ok, why)
    inventory = {item["path"]: item for item in core.get("inventory", [])}
    components = {c["path"]: c for c in bundle.get("components", [])}
    rep.check("manifest", "inventory matches components", set(inventory) == set(components) and len(inventory) == len(core.get("inventory", [])))
    by_media = {}
    for path, item in inventory.items():
        comp = components.get(path)
        if comp is None:
            continue
        meta = {k: comp[k] for k in ("path", "mediaType", "disposition", "digest", "size", "reasonCode") if k in comp}
        rep.check("manifest", f"{path}: inventory entry", jcs(meta) == jcs(item))
        if comp.get("disposition") == "included":
            content = comp.get("content")
            raw = jcs(content)
            rep.check("manifest", f"{path}: size {len(raw)} B + digest", str(len(raw)) == item.get("size") and sha256_tag(raw) == item.get("digest"))
            by_media.setdefault(comp.get("mediaType"), []).extend(content if isinstance(content, list) else [])

    entries = by_media.get(MEDIA["entries"], [])
    checkpoints = by_media.get(MEDIA["checkpoints"], [])
    inclusions = by_media.get(MEDIA["inclusion"], [])
    observations = by_media.get(MEDIA["observations"], [])

    # entries ----------------------------------------------------------------
    rep.check("entries", "at least one entry", len(entries) > 0)
    for e in entries:
        c = e["core"]
        seq = c["sequence"]
        rep.check("entries", f"#{seq} integritySuite", c.get("integritySuite") == "KYA-AUDIT-JCS-SHA256-JWS-2026")
        ev_digest = domain_digest("org.kya-os.audit.event.v1", c["event"])
        rep.check("entries", f"#{seq} event digest", ev_digest == c.get("eventDigest") == e.get("eventDigest"))
        rep.check("entries", f"#{seq} evidence-manifest digest", domain_digest("org.kya-os.audit.evidence-manifest.v1", evidence_manifest(c["event"])) == c.get("evidenceManifestDigest"))
        entry_digest = domain_digest("org.kya-os.audit.entry.v1", c)
        rep.check("entries", f"#{seq} entry digest", entry_digest == e.get("entryDigest"), "" if entry_digest == e.get("entryDigest") else f"recomputed {entry_digest[:23]}… ≠ stored {str(e.get('entryDigest'))[:23]}…")
        rc = e["recorderReceipt"]["core"]
        rep.check("entries", f"#{seq} receipt core rebuilt from entry", jcs(receipt_core(c, e["entryDigest"])) == jcs(rc))
        ok, why = jws_verify(e["recorderReceipt"].get("jws", ""), jcs(rc), c.get("recorder", {}), keys)
        rep.check("entries", f"#{seq} receipt JWS", ok, why)

    # chain ------------------------------------------------------------------
    ordered = sorted(entries, key=lambda e: int(e["core"]["sequence"]))
    if ordered:
        first = ordered[0]["core"]
        rep.check("chain", "genesis at sequence 0", first["sequence"] == "0" and first["previousEntryDigest"] is None and first["event"]["eventType"] == "ledger.epoch.started")
    for prev, cur in zip(ordered, ordered[1:]):
        pc, cc = prev["core"], cur["core"]
        rep.check("chain", f"#{cc['sequence']} follows #{pc['sequence']}", int(cc["sequence"]) == int(pc["sequence"]) + 1 and cc["ledgerId"] == pc["ledgerId"] and cc["ledgerEpochId"] == pc["ledgerEpochId"])
        linked = cc["previousEntryDigest"] == prev["entryDigest"]
        rep.check("chain", f"#{cc['sequence']} previousEntryDigest", linked, "" if linked else f"names {str(cc['previousEntryDigest'])[:23]}…, predecessor is {prev['entryDigest'][:23]}…")

    # checkpoint -------------------------------------------------------------
    rep.check("checkpoint", "at least one checkpoint", len(checkpoints) > 0)
    for cp in checkpoints:
        c = cp["core"]
        size = int(c["treeSize"])
        rep.check("checkpoint", "integritySuite", c.get("integritySuite") == "KYA-AUDIT-RFC9162-SHA256-JWS-2026")
        rep.check("checkpoint", "checkpoint digest", domain_digest("org.kya-os.audit.checkpoint.v1", c) == cp.get("checkpointDigest"))
        ok, why = jws_verify(cp.get("jws", ""), jcs(c), c.get("issuer", {}), keys)
        rep.check("checkpoint", "issuer JWS", ok, why)
        covered = [e for e in ordered if e["core"]["ledgerId"] == c["ledgerId"] and e["core"]["ledgerEpochId"] == c["ledgerEpochId"] and int(e["core"]["sequence"]) < size]
        rep.check("checkpoint", f"range: {size} entries, seq {c['firstSequence']}…{c['lastSequence']}", len(covered) == size and covered and covered[0]["core"]["sequence"] == c["firstSequence"] and covered[-1]["core"]["sequence"] == c["lastSequence"] and covered[-1]["entryDigest"] == c["headEntryDigest"])
        if len(covered) == size and covered:
            root = merkle_root([e["entryDigest"] for e in covered])
            rep.check("checkpoint", "RFC 9162 root recomputed from entry digests", root == c["rootDigest"], "" if root == c["rootDigest"] else f"recomputed {root[:23]}… ≠ signed {c['rootDigest'][:23]}…")

    # inclusion --------------------------------------------------------------
    cps = {cp["checkpointDigest"]: cp for cp in checkpoints}
    ents = {(e["core"]["sequence"], e["entryDigest"]): e for e in entries}
    rep.check("inclusion", "proofs present for every checkpointed entry", len(inclusions) >= sum(int(cp["core"]["treeSize"]) for cp in checkpoints))
    for item in inclusions:
        cp = cps.get(item["checkpointDigest"])
        entry = ents.get((item["sequence"], item["entryDigest"]))
        proof = item["proof"]
        ok = (cp is not None and entry is not None and proof["treeSize"] == cp["core"]["treeSize"] and proof["leafIndex"] == item["sequence"]
              and verify_inclusion(item["entryDigest"], int(proof["leafIndex"]), int(proof["treeSize"]), cp["core"]["rootDigest"], proof["auditPath"]))
        rep.check("inclusion", f"#{item['sequence']} audit path → root", ok)

    # witness ----------------------------------------------------------------
    if observations:
        for ob in observations:
            c = ob["core"]
            cp = cps.get(c["checkpointDigest"])
            rep.check("witness", "observation names a bundled checkpoint", cp is not None and c["ledgerId"] == cp["core"]["ledgerId"] and c["ledgerEpochId"] == cp["core"]["ledgerEpochId"] and c["treeSize"] == cp["core"]["treeSize"])
            rep.check("witness", "observation digest", domain_digest("org.kya-os.audit.observation.v1", c) == ob.get("observationDigest"))
            ok, why = jws_verify(ob.get("jws", ""), jcs(c), c.get("observer", {}), keys)
            rep.check("witness", f"observer JWS ({c.get('observer', {}).get('did', '?')})", ok, why)
    else:
        rep.check("witness", "no observation receipts in bundle (indeterminate, not a failure)", True)
    return rep


def main() -> int:
    ap = argparse.ArgumentParser(description="stdlib verifier for a KYA-OS audit replay bundle")
    ap.add_argument("bundle")
    ap.add_argument("--keys", required=True, help="keys.json: {keys:[{kid, jwk}]} — the ONLY source of trust")
    ap.add_argument("--quiet", action="store_true", help="print verdicts only")
    args = ap.parse_args()
    with open(args.bundle, encoding="utf-8") as fh:
        bundle = json.load(fh)
    with open(args.keys, encoding="utf-8") as fh:
        keyfile = json.load(fh)
    keys = {k["kid"]: k["jwk"] for k in keyfile["keys"]}
    rep = verify_bundle(bundle, keys)
    failures = [{"section": s, **c} for s, cs in rep.sections.items() for c in cs if not c["ok"]]
    shown, seen = [], {}
    for f in failures:  # at most three per section; the rest is a count
        seen[f["section"]] = seen.get(f["section"], 0) + 1
        if seen[f["section"]] <= 3:
            shown.append(f)
    out = {"bundle": args.bundle, "verdict": "valid" if rep.ok else "invalid", "dimensions": rep.verdicts(),
           "checks": sum(len(v) for v in rep.sections.values()), "failed": len(failures),
           "failures": shown + ([{"note": f"… and {len(failures) - len(shown)} more"}] if len(failures) > len(shown) else [])}
    if not args.quiet:
        out["sections"] = rep.sections
    print(json.dumps(out, indent=1))
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
