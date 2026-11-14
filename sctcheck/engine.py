"""Admission engine: verify embedded SCTs against the frozen log policy (lab HMAC)."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

ENTRY_TYPE_PRECERT = 1
SCT_VERSION = 0
DEFAULT_MIN_SCTS = 2
REASON_ORDER = (
    "unknown_log",
    "retired_log",
    "timestamp",
    "tbs_mismatch",
    "bad_sct",
    "too_few",
)


def compute_tbs_hash(tbs_precert: Any) -> str:
    """Lowercase hex SHA-256 of the canonical TBS JSON, or of its UTF-8 bytes."""
    if isinstance(tbs_precert, dict):
        raw = json.dumps(
            tbs_precert, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    else:
        raw = str(tbs_precert).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _signed_input(sct: dict[str, Any], signed_tbs_hash: str) -> bytes:
    payload = {
        "entry_type": int(sct.get("entry_type", ENTRY_TYPE_PRECERT)),
        "log_id": sct.get("log_id"),
        "tbs_hash": signed_tbs_hash,
        "timestamp": int(sct["timestamp"]),
        "v": SCT_VERSION,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _signature_valid(
    sct: dict[str, Any], key_hex: str | None, signed_tbs_hash: str
) -> bool:
    if not key_hex:
        return False
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        return False
    expected = hmac.new(
        key, _signed_input(sct, signed_tbs_hash), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, str(sct.get("sig", "")).lower())


def admit(
    bundle: dict[str, Any], policy: dict[str, Any], keys: dict[str, str]
) -> dict[str, Any]:
    computed_hash = compute_tbs_hash(bundle.get("tbs_precert"))
    now = bundle.get("now")
    logs = {entry["log_id"]: entry for entry in policy.get("logs", [])}
    min_scts = policy.get("min_scts", DEFAULT_MIN_SCTS)

    reason_set: set[str] = set()
    notes: list[str] = []
    accepted_logs: set[str] = set()

    for index, sct in enumerate(bundle.get("scts") or []):
        log_id = sct.get("log_id")
        log = logs.get(log_id)
        if log is None:
            reason_set.add("unknown_log")
            notes.append(f"sct[{index}] {log_id}: unknown_log")
            continue

        failures: list[str] = []
        timestamp = sct.get("timestamp")
        if timestamp < log.get("start", 0) or timestamp > now:
            failures.append("timestamp")
        if log.get("retired") and timestamp >= log.get("retired_at"):
            failures.append("retired_log")

        carried_hash = sct.get("tbs_hash")
        if carried_hash is not None and carried_hash != computed_hash:
            failures.append("tbs_mismatch")

        signed_hash = carried_hash if carried_hash is not None else computed_hash
        if not _signature_valid(sct, keys.get(log_id), signed_hash):
            failures.append("bad_sct")

        if failures:
            reason_set.update(failures)
            notes.append(
                f"sct[{index}] {log_id}: {', '.join(failures)}"
            )
        else:
            accepted_logs.add(log_id)

    accepted = sorted(accepted_logs)
    if not reason_set and len(accepted) < min_scts:
        reason_set.add("too_few")
        notes.append(
            f"too_few: {len(accepted)} distinct log(s) accepted, "
            f"policy requires {min_scts}"
        )

    reason_codes = [code for code in REASON_ORDER if code in reason_set]
    decision = "allow" if not reason_codes else "deny"
    if decision == "allow":
        notes.append(
            f"all SCTs accepted; quorum met with {len(accepted)} distinct log(s)"
        )

    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "accepted_logs": accepted,
        "notes": notes,
    }
