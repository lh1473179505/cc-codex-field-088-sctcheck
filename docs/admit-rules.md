# Admit rules

Reuse `load_json`. The bundle holds a precertificate TBS (`tbs_precert`), an optional `tbs_final`, `now`, and a list of SCTs. This lab does not use ASN.1. Log HMAC keys are in `--keys`, keyed by `log_id`.

The TBS hash is the lowercase hex SHA-256 of `json.dumps(tbs_precert, sort_keys=True, separators=(",", ":"))` when the TBS is an object, or of the UTF-8 bytes if it is a string. SCTs sign that hash.

The signed SCT input is `json.dumps({"entry_type": int, "log_id": ..., "tbs_hash": ..., "timestamp": int, "v": 0}, sort_keys=True, separators=(",", ":"))`. `sig` is lowercase hex HMAC-SHA256 of those bytes with the log key. `entry_type` is 1 for a precertificate in this lab.

## Log list and time

`policy.logs` is a frozen list of `{log_id, start, retired, retired_at}`. An SCT whose `log_id` is not in that list is `unknown_log`. If the log has `retired` true and `timestamp >= retired_at`, that is `retired_log`. A timestamp earlier than `start`, or later than `bundle.now`, is `timestamp`.

If an SCT carries `tbs_hash` and it does not equal the computed precert TBS hash, that is `tbs_mismatch`. A signature that does not verify is `bad_sct`.

## Quorum

`policy.min_scts` (default 2) is the number of *distinct* logs that must contribute a fully accepted SCT. Duplicate SCTs from the same log count once. If fewer than that remain after the checks above, `too_few`. Any failed SCT still contributes its reason code, so a bundle that includes a retired or unknown log in addition to two good SCTs is denied.

## Report and exit

Report: `decision`, `reason_codes`, `accepted_logs`, `notes`. Stable order: `unknown_log`, `retired_log`, `timestamp`, `tbs_mismatch`, `bad_sct`, `too_few`.

`allow` exits 0, `deny` exits 1, load failures exit 2.

## Public fixtures

`--policy fixtures/policy.json --keys fixtures/keys.json --bundle fixtures/bundles/NAME.json`:

- `ok-two-logs.json` → allow
- `unknown-log.json` → deny `unknown_log`
- `retired-log.json` → deny `retired_log`
- `future-ts.json` → deny `timestamp`
- `tbs-mismatch.json` → deny `tbs_mismatch`
- `bad-sct.json` → deny `bad_sct`
- `too-few.json` → deny `too_few`
- `one-good-one-retired.json` → deny `retired_log`
