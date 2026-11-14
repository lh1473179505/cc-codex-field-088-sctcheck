# sctcheck

A certificate-transparency SCT admission tool for a precert TBS and a frozen log list (lab HMAC).

`python -m sctcheck inspect --bundle fixtures/bundles/ok-two-logs.json` already prints the log ids. `admit` is still a stub.

Standard library only. No Docker, no live CT logs.
