#!/usr/bin/env python3
"""Verifier of the Payment Authority Profile execution vector corpus
(experimental/payment-authority/SPEC-PAYMENT-EXECUTION.md).

Standard library only: it reproduces every vector's expected result from the
document's rules and compares it with the corpus. It reuses the Core Authority
verifier beside it for RFC 8785, digests, the intent checks, and the answer
proof check. To the intents inside `arguments` vectors it applies Core's
member check and checks V1 to V4 (Core section 8.7); to the results of
`answers` vectors, its own restatement of `payment-answer.schema.json` and
the rules of section 9 that no schema states. Full JSON Schema validation is
`execution-schemas.test.ts`'s. It also checks the `answerProofs` vectors of
the Core corpus, whose members section 13.3 defines.

    python3 experimental/payment-authority/vectors/verify_execution_vectors.py

Exit status 0 means every vector reproduced; any mismatch is printed and the
exit status is 1.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator, Optional

sys.dont_write_bytecode = True  # importing the Core verifier leaves no __pycache__ in the repository
sys.path.insert(0, str(Path(__file__).parent))
from verify_vectors import (  # noqa: E402
    CORPUS as CORE_CORPUS,
    data_model,
    domain_digest,
    has_proto_member,
    intent_members_ok,
    jcs,
    valid_amount,
    valid_intent_semantics,
    verify_answer_proof,
)

CORPUS = Path(__file__).with_name("payment-execution-vectors.json")
PROFILE = "org.kya-os/payments.v1"
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
SKEW_MS = 60_000  # the profile clock skew (Core section 7.1)

# ---------------------------------------------------------------------------
# Section 4.2: the payment argument
# ---------------------------------------------------------------------------


CARRIER = "org.kya-os/delegation-credentials"  # section 4.3


class _Duplicated(dict):
    """An object that held two members of one name (the later value kept); `names` are the repeated ones."""

    names: frozenset = frozenset()


def _mark_duplicates(pairs: list) -> dict:
    names = [name for name, _ in pairs]  # names compared once escapes are decoded
    repeated = frozenset(name for name in names if names.count(name) > 1)
    if not repeated:
        return dict(pairs)
    marked = _Duplicated(pairs)
    marked.names = repeated
    return marked


def _defects(value: Any, path: tuple = ()) -> Iterator[tuple]:
    """The paths at which a parsed message is not a canonical value (Core section 10)."""
    if isinstance(value, _Duplicated):
        yield from (path + (name,) for name in value.names)  # a repeated member lies where it is named
    if isinstance(value, dict):
        for key, item in value.items():
            if not _well_formed(key):
                yield path + (key,)
            yield from _defects(item, path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _defects(item, path + (index,))
    elif not (_well_formed(value) and _canonical_numbers(value)):
        yield path


def _well_formed(value: Any) -> bool:
    """No lone surrogate in any string or member name (Core section 10)."""
    if isinstance(value, str):
        return not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    if isinstance(value, dict):
        return all(_well_formed(k) and _well_formed(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_well_formed(item) for item in value)
    return True


def _canonical_numbers(value: Any) -> bool:
    """Core section 10: every number finite, and an integral one a safe integer."""
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            return False
        return not (float(value).is_integer() and abs(value) > 2**53 - 1)
    if isinstance(value, dict):
        return all(_canonical_numbers(v) for v in value.values())
    if isinstance(value, list):
        return all(_canonical_numbers(v) for v in value)
    return True


def _text(value: Any, low: int, high: int, banned: str) -> bool:
    return isinstance(value, str) and low <= len(value) <= high and not any(ch in value for ch in banned)


ARGUMENT_REQUIRED = {"profile", "idempotencyKey", "intent", "delegationDigest"}
ARGUMENT_MEMBERS = ARGUMENT_REQUIRED | {"approvalEvidence"}


MAX_MESSAGE_BYTES = 2_097_152
MAX_MESSAGE_DEPTH = 64


def message_depth(text: str) -> int:
    """Nesting depth of a JSON text (the outermost object is depth 1), read without parsing it,
    so no input can exhaust a parser's stack."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def valid_payment_argument(message: Any) -> bool:
    """Section 4.2, for a message that is a canonical value."""
    params = message.get("params") if isinstance(message, dict) else None
    if not isinstance(params, dict):
        return False
    arguments = params.get("arguments")
    payment = arguments.get("payment") if isinstance(arguments, dict) else None
    if not isinstance(payment, dict) or has_proto_member(payment):
        return False
    payment = data_model(payment)
    if not ARGUMENT_REQUIRED <= set(payment) <= ARGUMENT_MEMBERS:
        return False
    if payment["profile"] != PROFILE:
        return False
    if not _text(payment["idempotencyKey"], 1, 256, "\r\n\u0000"):
        return False
    if not (isinstance(payment["delegationDigest"], str) and DIGEST.fullmatch(payment["delegationDigest"])):
        return False
    if "approvalEvidence" in payment:
        evidence = payment["approvalEvidence"]
        if not (isinstance(evidence, dict) and set(evidence) == {"type", "format", "value"}):
            return False
        if not (_text(evidence["type"], 1, 2048, "\r\n") and _text(evidence["format"], 1, 256, "\r\n")):
            return False
        value = evidence["value"]
        if not (isinstance(value, str) and len(value) >= 1 and len(value.encode("utf-8")) <= 65536):
            return False
    intent = payment["intent"]
    try:
        return intent_members_ok(intent) and valid_intent_semantics(intent)
    except (KeyError, TypeError, AttributeError):
        return False


def argument(vector: dict) -> dict:
    # Section 4.2: the whole message is bounded before it is parsed.
    if len(vector["text"].encode("utf-8")) > MAX_MESSAGE_BYTES or message_depth(vector["text"]) > MAX_MESSAGE_DEPTH:
        return {"valid": False, "code": "PAYMENT_REQUEST_INVALID"}
    try:
        message = json.loads(vector["text"], object_pairs_hook=_mark_duplicates)
    except ValueError:
        return {"valid": False, "code": "PAYMENT_REQUEST_INVALID"}
    # Section 4.2: duplicate member names, ill-formed Unicode, and numbers that are not canonical
    # values anywhere in the message, `params._meta` included; the reason follows where they lie.
    defects = list(_defects(message))
    if any(path[:3] == ("params", "arguments", "payment") for path in defects):
        return {"valid": False, "code": "PAYMENT_ARTIFACT_INVALID"}
    if any(path[:3] == ("params", "_meta", CARRIER) and len(path) > 3 for path in defects):
        return {"valid": False, "code": "PAYMENT_DELEGATION_INVALID"}  # inside a credential (Core section 10)
    if defects:
        return {"valid": False, "code": "PAYMENT_REQUEST_INVALID"}
    if valid_payment_argument(message):
        return {"valid": True}
    return {"valid": False, "code": "PAYMENT_ARTIFACT_INVALID"}


# ---------------------------------------------------------------------------
# Sections 4.1 and 5.1: the operation identifier and the scope
# ---------------------------------------------------------------------------


def scope(vector: dict) -> dict:
    refused = {"valid": False, "code": "PAYMENT_REQUEST_INVALID"}
    tool, tenant, caller = vector["toolName"], vector["tenant"], vector["caller"]
    if not _text(tool, 1, 256, "#\r\n"):
        return refused
    # Section 5.1: a tenant is configuration, checked when it is loaded, so only the caller is checked here.
    if not _text(caller, 1, 512, "\r\n"):
        return refused
    value = PROFILE + ":" + jcs({"tenant": tenant, "caller": caller, "operation": "tools/call#" + tool})
    if len(value) > 2048:
        return refused
    return {"scope": value}


# ---------------------------------------------------------------------------
# Sections 5.2 and 7.2, steps 9 and 14
# ---------------------------------------------------------------------------

PAST_REVERSIBLE = {"submitted", "settlement_pending", "settled", "failed"}


def idempotency(vector: dict) -> str:
    request, journal = vector["request"], vector["journal"]
    bound = [a for a in journal if (a["scope"], a["key"]) == (request["scope"], request["key"])]
    if bound:
        attempt = bound[0]
        if attempt["requestDigest"] != request["requestDigest"]:
            return "PAYMENT_IDEMPOTENCY_CONFLICT"
        if attempt["state"] in PAST_REVERSIBLE or attempt["claimed"]:
            return "answer"
        # A released `authorized` attempt: a resumption, under the attempt's payment identity.
        return "claim" if attempt["paymentIdentity"] == request["paymentIdentity"] else "PAYMENT_REPLAY"
    if any(a["intentDigest"] == request["intentDigest"] for a in journal):
        return "PAYMENT_IDEMPOTENCY_CONFLICT"
    if any(a["paymentIdentity"] == request["paymentIdentity"] for a in journal):
        return "PAYMENT_REPLAY"
    return "create"


# ---------------------------------------------------------------------------
# Section 7.4: expiry at each check
# ---------------------------------------------------------------------------


def _refuse(code: str, retryable: bool) -> dict:
    return {"action": "refuse", "code": code, "retryable": retryable}


def _expired(bounds: dict, name: str, now: int) -> bool:
    return name in bounds and now >= bounds[name]


def _earliest_reason(expired: dict, own: str, own_code: str) -> str:
    """`own_code` when the bound `own` is no later than every other expired bound."""
    at = expired.get(own)
    return own_code if at is not None and at <= min(expired.values()) else "PAYMENT_AUTHORITY_EXPIRED"


def expiry(vector: dict) -> dict:
    now, fixed, renewable = vector["now"], vector["fixed"], vector["renewable"]
    status, reevaluation = vector["status"], vector["reevaluation"]
    expired_fixed = {name: at for name, at in fixed.items() if now >= at}
    expired_renewable = {name: at for name, at in renewable.items() if now >= at}
    if vector["phase"] == "call":
        # Step 17 reads only the bounds: the reason of section 7.4's first row for fixed bounds,
        # else the earliest renewable bound's.
        if expired_fixed:
            return {"action": "fail", "code": _earliest_reason(expired_fixed, "quoteExpiresAt", "PAYMENT_QUOTE_EXPIRED")}
        if expired_renewable:
            return {"action": "fail",
                    "code": _earliest_reason(expired_renewable, "railTermsExpiresAt", "PAYMENT_QUOTE_EXPIRED")}
        return {"action": "proceed"}
    if vector["phase"] == "reevaluation":
        # Step 13 checks every bound, refusing with the claim column's reasons, then re-evaluates.
        if expired_fixed:
            return _refuse(_earliest_reason(expired_fixed, "quoteExpiresAt", "PAYMENT_QUOTE_EXPIRED"), False)
        if expired_renewable:
            return _refuse(_earliest_reason(expired_renewable, "railTermsExpiresAt", "PAYMENT_QUOTE_EXPIRED"), True)
        if reevaluation == "fail":
            # Section 9.2, cause 4: a rule that failed on fees or an unbound quote failed on uncovered input.
            return _refuse("PAYMENT_CONSTRAINT_DENIED", vector["failedOn"] != "bound-quote")
        if reevaluation == "incomplete":
            return _refuse("PAYMENT_CONSTRAINT_INVALID", True)  # Core section 8.4.4; section 9.2, cause 5
        return {"action": "proceed"}
    if vector["phase"] == "decision":
        # The steps in order; the first that fails decides (section 7.4).
        if _expired(renewable, "requestProofExpires", now):
            return _refuse("PROOF_INVALID", True)  # step 6
        if _expired(fixed, "intentExpiresAt", now):
            return _refuse("PAYMENT_AUTHORITY_EXPIRED", False)  # step 10
        # Step 11 is Core section 8.4.6: its step 5, then 8, 9, and 10.
        if _expired(fixed, "delegationExpiresAt", now):
            return _refuse("PAYMENT_DELEGATION_INVALID", False)
        if status == "revoked":
            return _refuse("PAYMENT_DELEGATION_REVOKED", False)
        if status in ("unavailable", "not-live"):
            return _refuse("PAYMENT_AUTHORITY_STALE", True)
        if _expired(fixed, "approvalExpiresAt", now):
            return _refuse("PAYMENT_APPROVAL_INVALID", False)
        if _expired(fixed, "caveatExpiresAt", now):
            return _refuse("PAYMENT_CONSTRAINT_DENIED", False)
        if _expired(fixed, "quoteExpiresAt", now):
            return _refuse("PAYMENT_QUOTE_EXPIRED", False)  # step 12
        if _expired(renewable, "railTermsExpiresAt", now):
            return _refuse("PAYMENT_QUOTE_EXPIRED", True)
        return {"action": "proceed"}
    # Under a claim, the first row of the table that applies decides. A walk that reads only live
    # lists renews the status freshness (step 15); one that does not leaves the decision's in force.
    if status in ("live", "revoked"):
        expired_renewable.pop("statusFreshUntil", None)
    if expired_fixed:
        return {"action": "fail", "code": _earliest_reason(expired_fixed, "quoteExpiresAt", "PAYMENT_QUOTE_EXPIRED")}
    if expired_renewable:
        return {"action": "release", "retryable": True,
                "code": _earliest_reason(expired_renewable, "railTermsExpiresAt", "PAYMENT_QUOTE_EXPIRED")}
    if status == "revoked":
        return {"action": "fail", "code": "PAYMENT_DELEGATION_REVOKED"}
    if status in ("unavailable", "not-live", "incomplete"):
        return {"action": "release", "code": "PAYMENT_AUTHORITY_STALE", "retryable": True}
    if reevaluation == "fail":
        return {"action": "fail", "code": "PAYMENT_AUTHORITY_RECHECK_FAILED"}
    if reevaluation == "incomplete":
        return {"action": "release", "code": "PAYMENT_CONSTRAINT_INVALID", "retryable": True}
    return {"action": "proceed"}


# ---------------------------------------------------------------------------
# Sections 6.4 and 6.5: after a loss or a deletion of journal records
# ---------------------------------------------------------------------------


def quarantine(vector: dict) -> dict:
    """Sections 6.4 and 6.5: the refusals after a loss of records and after a deletion."""
    horizon, cutoff, attempt = vector["horizon"], vector["retentionCutoff"], vector["attempt"]
    # Section 9.4: whichever step refuses, no refusal reports on an intent in these states.
    if attempt is None:
        if horizon is not None and vector["intentCreatedAt"] < horizon + SKEW_MS:  # under the horizon
            return {"action": "refuse", "code": "PAYMENT_JOURNAL_INDETERMINATE", "retryable": False,
                    "reportsAttempt": False}
        if cutoff is not None and vector["intentExpiresAt"] <= cutoff:  # at or before the retention cutoff
            return {"action": "refuse", "code": "PAYMENT_JOURNAL_INDETERMINATE", "retryable": False,
                    "reportsAttempt": False}
        return {"action": "proceed", "reportsAttempt": True}
    # Section 6.4: only a write under the horizon in force ends a hold-back.
    held_back = (horizon is not None and attempt["state"] not in ("settled", "failed")
                 and not attempt["writtenUnderHorizon"])
    if held_back:
        return {"action": "refuse", "code": "PAYMENT_JOURNAL_INDETERMINATE", "retryable": True,
                "reportsAttempt": False}
    return {"action": "proceed", "reportsAttempt": True}


# ---------------------------------------------------------------------------
# Section 9: answers, apart from the answer proof
# ---------------------------------------------------------------------------

STATES = ("authorized", "submitted", "settlement_pending", "settled", "failed")
OUTCOME_REASONS = {"payment_failed", "payment_quote_expired", "payment_authority_expired",
                   "payment_delegation_revoked", "payment_authority_recheck_failed", "payment_denied"}
CORE_REASONS = {
    "payment_profile_unsupported", "payment_delegation_invalid", "payment_delegation_revoked",
    "payment_action_not_granted", "payment_caveat_unsupported", "payment_approval_required",
    "payment_request_invalid", "payment_artifact_invalid", "payment_artifact_unauthenticated",
    "payment_extension_unsupported", "payment_extension_invalid", "payment_intent_mismatch",
    "payment_payer_mismatch", "payment_request_mismatch", "payment_authority_mismatch",
    "payment_authority_expired", "payment_authority_stale", "payment_authority_recheck_failed",
    "payment_approval_invalid", "payment_constraint_invalid", "payment_constraint_widening",
    "payment_constraint_denied", "payment_quote_expired", "payment_failed", "payment_evidence_invalid",
    "payment_state_transition_invalid", "payment_outcome_stream_invalid", "payment_configuration_invalid",
    "payment_denied",
}
EXECUTION_REASONS = {
    "payment_idempotency_conflict", "payment_replay", "payment_attempt_conflict", "payment_journal_unavailable",
    "payment_journal_indeterminate", "payment_rail_unsupported", "payment_offer_mismatch",
    "payment_credential_invalid", "payment_funding_authority_failed",
}
# Section 9.2: never a reason that only an error before authentication carries (the proof and other negotiation
# reasons are not payment reasons, so only these two of Core's are), nor one only an Evidence Consumer reports,
# nor an outcome reason that only a failed attempt carries.
BEFORE_AUTHENTICATION_ONLY = {"payment_profile_unsupported", "payment_artifact_invalid"}
CONSUMER_ONLY = {"payment_state_transition_invalid", "payment_outcome_stream_invalid"}
ATTEMPT_ONLY = {"payment_failed", "payment_authority_recheck_failed"}
REFUSAL_REASONS = (CORE_REASONS | EXECUTION_REASONS) - BEFORE_AUTHENTICATION_ONLY - CONSUMER_ONLY - ATTEMPT_ONLY
FINALITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,63}")
JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _reference(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 2048


def valid_attempt(a: Any) -> bool:
    members = {"attemptId", "state", "intentDigest", "authorizationDigest", "rail", "effectAmount",
               "effectAmountMismatch", "correction", "finality", "reason", "evidenceComplete"}
    required = {"attemptId", "state", "intentDigest", "authorizationDigest", "evidenceComplete"}
    if not (isinstance(a, dict) and required <= set(a) <= members):
        return False
    state = a["state"]
    if not (_reference(a["attemptId"]) and state in STATES and isinstance(a["evidenceComplete"], bool)):
        return False
    if not all(isinstance(a[k], str) and DIGEST.fullmatch(a[k]) for k in ("intentDigest", "authorizationDigest")):
        return False
    rail = a.get("rail")
    if rail is not None and not (isinstance(rail, dict) and rail and set(rail) <= {"transactionRef", "reconciliationRef"}
                                 and all(_reference(v) for v in rail.values())):
        return False
    for flag in ("effectAmountMismatch", "correction"):
        if flag in a and a[flag] is not True:
            return False
    if "finality" in a and not (isinstance(a["finality"], str) and FINALITY.fullmatch(a["finality"])):
        return False
    if "effectAmount" in a and not valid_amount(a["effectAmount"]):
        return False
    reason = a.get("reason")
    if reason is not None and not (isinstance(reason, dict) and set(reason) == {"code", "newIntentMaySucceed"}
                                   and reason["code"] in OUTCOME_REASONS
                                   and isinstance(reason["newIntentMaySucceed"], bool)):
        return False
    # Section 9.1: presence by state.
    if state == "settled":
        if "effectAmount" not in a or rail is None or "transactionRef" not in rail or "reconciliationRef" in rail:
            return False
    elif any(k in a for k in ("effectAmount", "effectAmountMismatch", "finality")):
        return False
    if state == "settlement_pending" and (rail is None or "reconciliationRef" not in rail):
        return False
    if state in ("authorized", "submitted", "failed") and ("rail" in a or "correction" in a):
        return False
    return (state == "failed") == ("reason" in a)


def valid_refusal(r: Any) -> bool:
    members = {"reason", "retryable", "intentDigest", "attemptRecorded", "attempt", "requireApproval"}
    if not (isinstance(r, dict) and {"reason", "retryable", "intentDigest"} <= set(r) <= members):
        return False
    if r["reason"] not in REFUSAL_REASONS or not isinstance(r["retryable"], bool):
        return False
    if not (isinstance(r["intentDigest"], str) and DIGEST.fullmatch(r["intentDigest"])):
        return False
    if "attemptRecorded" in r and not isinstance(r["attemptRecorded"], bool):
        return False
    if "attempt" in r and (r.get("attemptRecorded") is not True or not valid_attempt(r["attempt"])):
        return False
    challenge = r["reason"] == "payment_approval_required"
    if challenge != ("requireApproval" in r):
        return False
    if challenge:
        requirement = r["requireApproval"]
        modes = requirement.get("modes") if isinstance(requirement, dict) else None
        if not (isinstance(modes, list) and 1 <= len(modes) <= 3 and len(set(modes)) == len(modes)
                and set(modes) <= {"human-present", "human-not-present", "standing-policy"}):
            return False
    return True


def valid_answer(result: Any) -> bool:
    if not (isinstance(result, dict) and {"resultType", "content", "structuredContent", "_meta"} <= set(result)
            <= {"resultType", "isError", "content", "structuredContent", "_meta"}):
        return False
    if result["resultType"] != "complete":
        return False
    meta = result["_meta"]
    if not (isinstance(meta, dict) and isinstance(meta.get("org.kya-os/payment-answer"), str)
            and JWS.fullmatch(meta["org.kya-os/payment-answer"])):
        return False
    content = result["content"]
    if not (isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict)
            and set(content[0]) == {"type", "text"} and content[0]["type"] == "text"
            and isinstance(content[0]["text"], str)):
        return False
    body = result["structuredContent"]
    if not isinstance(body, dict) or len(body) != 1:
        return False
    if "payment" in body:
        if not valid_attempt(body["payment"]) or result.get("isError", False) is not False:
            return False
    elif "paymentRefusal" in body:
        if not valid_refusal(body["paymentRefusal"]) or result.get("isError") is not True:
            return False
    else:
        return False
    # Section 9: the text block is a JSON text whose value equals structuredContent.
    try:
        return data_model(json.loads(content[0]["text"])) == data_model(body)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Section 10.2: the client's decisions
# ---------------------------------------------------------------------------

# The view's order (section 10.1); a correction to `settlement_pending` sits after `failed`.
ORDER = {"authorized": 0, "submitted": 1, "settlement_pending": 2, "failed": 3, "corrected_pending": 4, "settled": 5}


def _rank(attempt: dict) -> str:
    if attempt["state"] == "settlement_pending" and attempt.get("correction") is True:
        return "corrected_pending"
    return attempt["state"]


def client(vector: dict) -> list:
    presenter = vector["intent"]["presenter"]
    expires = vector["intent"]["expiresAt"]
    bound = expires + SKEW_MS + vector["reconcileInterval"]
    view: Optional[str] = None
    corrected = False
    first_shown: Optional[int] = None
    replaced = False
    decision: Optional[str] = None
    out = []
    for event in vector["events"]:
        kind = event["kind"]
        if kind == "replace":
            assert decision == "may-replace", "a replacement is taken only after may-replace"
            replaced, decision = True, "replaced"
            out.append(decision)
            continue
        refusal = event.get("paymentRefusal") if kind == "refusal" else None
        shown = event.get("payment") if kind == "payment" else (refusal or {}).get("attempt")
        advanced = False
        if shown is not None:
            rank = _rank(shown)
            if rank == "corrected_pending" or (shown.get("correction") is True):
                corrected = True
            if view is None or ORDER[rank] > ORDER[view]:
                view, advanced = rank, True
            if first_shown is None:
                first_shown = event["receivedAt"]
        sent = event["sentAt"]
        recorded = (refusal or {}).get("attemptRecorded")
        definitive = refusal is not None and refusal["retryable"] is False
        reason = (refusal or {}).get("reason")

        if decision == "done":
            pass  # row 1
        elif decision == "resolve-with-payer":  # row 2
            if shown is not None and shown["state"] == "settled" and not replaced:
                decision = "done"
        elif replaced:  # row 3
            decision = ("resolve-with-payer" if advanced and view in ("submitted", "settlement_pending",
                                                                      "corrected_pending", "settled")
                        else "replaced")
        elif view == "settled":
            decision = "done"  # row 4
        elif shown is not None and shown["state"] == "failed" and view == "corrected_pending":
            decision = "resolve-with-payer"  # row 5
        elif reason == "payment_journal_indeterminate" and definitive:
            decision = "resolve-with-payer"  # row 6
        elif recorded is True and refusal.get("attempt") is None:
            decision = "resolve-with-payer"  # row 7
        elif recorded is False and first_shown is not None and sent > first_shown:
            decision = "resolve-with-payer"  # row 8
        elif view == "failed" and not corrected:
            decision = "may-replace"  # row 9
        elif view in ("settlement_pending", "corrected_pending"):
            decision = "repeat"  # row 10
        elif view in ("authorized", "submitted"):
            decision = "resolve-with-payer" if sent >= bound else "repeat"  # row 11
        elif presenter and recorded is False and sent >= expires + SKEW_MS:
            decision = "may-replace"  # row 12
        elif sent >= bound:
            decision = "resolve-with-payer"  # row 13
        elif reason == "payment_approval_required":
            decision = "obtain-approval"  # row 14
        elif refusal is not None and refusal["retryable"] is True:
            decision = "repeat"  # row 15
        elif definitive and recorded is False and presenter:
            decision = "wait-then-repeat"  # row 16
        elif definitive:
            decision = "resolve-with-payer"  # row 17
        else:
            decision = "repeat"  # row 18
        out.append(decision)
    return out


# ---------------------------------------------------------------------------


def main() -> int:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    vectors = corpus["vectors"]
    failures: list = []
    checked = 0

    def check(label: str, expected: Any, actual: Any) -> None:
        nonlocal checked
        checked += 1
        if expected != actual:
            failures.append(f"{label}: expected {expected!r}, got {actual!r}")

    check("corpusDigest", corpus["corpusDigest"], domain_digest(corpus["corpusDomain"], data_model(vectors)))
    for v in vectors["arguments"]:
        check(f"argument {v['name']}", v["expect"], argument(v))
    for v in vectors["scopes"]:
        check(f"scope {v['name']}", v["expect"], scope(v))
    for v in vectors["idempotency"]:
        check(f"idempotency {v['name']}", v["expect"], idempotency(v))
    for v in vectors["expiry"]:
        check(f"expiry {v['name']}", v["expect"], expiry(v))
    for v in vectors["answers"]:
        check(f"answer {v['name']}", v["expect"], {"valid": valid_answer(v["result"])})
    for v in vectors["quarantine"]:
        check(f"quarantine {v['name']}", v["expect"], quarantine(v))
    for v in vectors["client"]:
        check(f"client {v['name']}", [e["decision"] for e in v["events"]], client(v))
    core = data_model(json.loads(CORE_CORPUS.read_text(encoding="utf-8")))
    proofs = 0
    for v in core["vectors"]["answerProofs"]:
        proofs += 1
        check(f"answer proof {v['name']}", v["verifies"], verify_answer_proof(v))

    if failures:
        print(f"FAIL: {len(failures)} of {checked} checks")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"OK: {checked - proofs} execution checks and {proofs} answer-proof checks of the Core corpus "
          f"reproduced by the Python verifier (corpus {corpus['corpusDigest']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
