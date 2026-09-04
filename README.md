# Evidence Quorum + Audit Contract Lab

**When a critical action happens, how many independent evidence paths must an adversary break to make it invisible?**

This is a small, auditable TypeScript lab. It replays **synthetic** tenants, maps who writes which evidence under which identity, computes a **min-cut** (minimum identities or stores to compromise to erase every trace), plants **nonce canaries**, classifies what we can actually observe as `HEALTHY` | `DEGRADED` | `UNKNOWN`, and emits an **Ed25519-signed coverage receipt** you can verify offline.

It is not a SIEM, not a connector pack, and not a legal attestation.

*FR — Laboratoire open-source : combien de chemins de preuve indépendants un attaquant doit briser pour rendre une action critique invisible. Un `npm start` rejoue des tenants synthétiques et signe un reçu vérifiable. Ce n’est pas une attestation légale.*

---

## Problem

Security reviews often list “logs in Okta, Splunk, and Jira” and call that defense in depth. Those streams are not independent if one human can delete all three. The interesting number is the **minimum hitting set**:

- each evidence path is a set of identities (or stores) that can erase it
- an adversary who wants *zero* traces must hit every set
- **identity min-cut** = fewest identities to compromise
- **component min-cut** = fewest stores / correlation groups to wipe

A nonce canary in WORM (object-lock) storage is a path with an **empty eraser set**. There is then no finite cut: the lab reports `unbounded`.

Observation is separate from design:

| Classification | Meaning |
|---|---|
| `HEALTHY` | Every path and canary is **present**, and design identity min-cut ≥ declared quorum |
| `DEGRADED` | A sensor is **missing**, or the design quorum is not met (including “all logs visible but one admin owns every path”) |
| `UNKNOWN` | Any sensor is **unreachable**. We do not guess. Unreachable is never coerced into all-good. |

---

## Less than five minutes

Requires **Node 20+**.

```bash
git clone https://github.com/Ovarixia/evidence-quorum-lab.git
cd evidence-quorum-lab
npm install
npm start
```

That single command:

1. Replays four disposable synthetic tenants (healthy, degraded, unknown, collapsed identities)
2. Places HMAC-SHA256 nonce canaries (seed-derived, reproducible)
3. Computes identity / component min-cuts per critical action
4. Writes signed receipts under `receipts/`
5. Verifies them against the demo public key

Then, independently:

```bash
npm test
npx tsx src/cli.ts verify receipts/synth-acme-healthy.receipt.json --trust fixtures/keys/demo-ed25519.pub.pem
```

Other commands:

```bash
npx tsx src/cli.ts list-tenants
npx tsx src/cli.ts run --tenant synth-acme-unknown
npx tsx src/cli.ts help
```

After `npm run build`, `node dist/cli.js run` works without `tsx`.

---

## What the receipt proves

A coverage receipt (`receipts/<tenant>.receipt.json`) is canonical JSON plus an Ed25519 signature.

**It proves**

- The payload was signed by the key embedded in the file (integrity).
- With `--trust fixtures/keys/demo-ed25519.pub.pem`, that key is the lab demo key.
- Min-cut and `HEALTHY|DEGRADED|UNKNOWN` **recompute** from the embedded graph (self-consistency).
- The run is **seed-locked**: same tenant seed → same canary nonces and `issuedAt` (`clock: seed-derived`).

**It does not prove** (non-claims, also copied into every receipt)

- That an action occurred in a real production system
- That you should trust the signer unless you pin `--trust`
- Legal, notarial, SOC 2, ISO 27001, or PCI attestation
- Anything about a live SIEM, IdP, PSP, or cluster (there are none)

The demo private key is **committed on purpose**. Anyone can sign lab receipts. Treat `eq-lab-demo-v1` as a pencil, not a root of trust.

---

## Critical actions in the lab

| Action | Evidence paths (writer → store → eraser) | Declared quorum |
|---|---|---|
| Admin privilege grant | IdP service → IdP audit → `idp-superadmin`; SSO bot → ITSM → `itsm-admin`; SIEM ingester → SIEM index → `siem-admin` | 2 identities |
| Production deploy | CI → git releases → `vcs-org-owner`; CI bot → OCI registry → `registry-admin`; API server → cluster audit → `cluster-admin` | 2 identities |
| Payment config change | PSP API → PSP audit → `psp-account-owner`; engineer → payments git → `vcs-org-owner`; finance → ITSM → `itsm-admin` | 2 identities |

Each action also plants a canary in `lab://object-lock/eq-canaries` with **no modeled eraser**.

Definitions live in `src/model/scenarios.ts`. Tenants live in `fixtures/tenants/`.

| Tenant | Fault / twist | Expected overall |
|---|---|---|
| `synth-acme-healthy` | Independent erasers, all sensors present | `HEALTHY` |
| `synth-acme-degraded` | SIEM copy of the privilege grant is **missing** | `DEGRADED` |
| `synth-acme-unknown` | Cluster audit sink is **unreachable** | `UNKNOWN` |
| `synth-acme-collapsed` | IdP + SIEM + ITSM admins aliased to `platform-superadmin` (logs still present, quorum 1) | `DEGRADED` |

---

## Layout

```
src/mincut.ts          enumerable hitting set (the quorum)
src/observe.ts         HEALTHY | DEGRADED | UNKNOWN (never fake all-good)
src/replay.ts          in-memory synthetic stores + faults
src/sign.ts            Ed25519 over canonical JSON
src/cli.ts             run / verify / list-tenants
fixtures/tenants/      disposable seeded tenants
fixtures/keys/         demo Ed25519 keypair (not a trust root)
tests/                 min-cut, observation, replay, receipts
```

Zero runtime dependencies. Cryptography is `node:crypto` Ed25519.

---

## Recovery assurance suite

This repository is stage A of [Cyber Recovery Assurance](https://github.com/Ovarixia/cyber-recovery-assurance). The integration runner verifies this lab's native signed receipt, binds its SHA-256 digest into EvidenceEnvelope v1, then permits TrustLink Repair and ReLink Gate to continue only through the signed A→B→C chain.

---

## License

MIT. See `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md`.
