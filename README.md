# sctcheck

A certificate-transparency SCT admission tool for a precert TBS and a frozen log list (lab HMAC).

`python -m sctcheck inspect --bundle fixtures/bundles/ok-two-logs.json` prints the embedded log ids. `admit` verifies every SCT against the frozen log policy and writes a JSON report:

```
python -m sctcheck admit \
  --bundle fixtures/bundles/ok-two-logs.json \
  --policy fixtures/policy.json \
  --keys fixtures/keys.json \
  --report /tmp/sctcheck-report.json
```

Exit code 0 means allow, 1 means deny, 2 means a snapshot, policy, or key file could not be loaded. See `docs/admit-rules.md` for the checks and `docs/report-schema.md` for the report schema.

Standard library only. No Docker, no live CT logs.
