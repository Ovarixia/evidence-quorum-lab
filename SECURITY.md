# Security

## This is a lab, not a production control plane

- The Ed25519 key under `fixtures/keys/` is a **demo key**. It is committed so anyone can reproduce signatures. Do not trust it as an organizational root.
- Receipt verification without `--trust` only proves the JSON is internally consistent and signed by *some* key embedded in the file.
- Pin `--trust fixtures/keys/demo-ed25519.pub.pem` only when you intend to accept lab-demo signatures.

## Reporting a vulnerability

If you find a bug in canonicalization, signature checking, or observation classification that would let a receipt claim `HEALTHY` while sensors are unreachable or missing:

1. Open a GitHub issue with a minimal failing test (preferred for this public lab), or
2. Email the repository owner listed on GitHub if you believe disclosure should be delayed.

Please do not report "we need a real SIEM connector" as a vulnerability. That is out of scope on purpose.

## Secrets

Do not add production credentials, customer logs, or real tenant identifiers. Fixtures must remain synthetic.
