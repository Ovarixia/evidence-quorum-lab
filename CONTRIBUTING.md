# Contributing

Thanks for wanting to improve a lab that stays honest about what it can prove.

## Ground rules

1. **Never fake all-good.** Unreachable sensors are `UNKNOWN`, not `HEALTHY`.
2. **No live enterprise connectors.** This repo is synthetic tenants only. A PR that adds Okta/Splunk/Stripe API clients will be rejected.
3. **No legal attestation language.** Receipts are coverage math plus an Ed25519 signature, not auditor letters.
4. **Keep the min-cut enumerable.** Hitting-set universe stays small so a reviewer can read the algorithm in `src/mincut.ts`.

## Dev loop

```bash
npm install
npm test
npm start
npx tsx src/cli.ts verify receipts/synth-acme-healthy.receipt.json
```

Node 20+ is required (Ed25519 via `node:crypto`, `node:test`).

## PR checklist

- Tests for any change to min-cut or observation rules
- README non-claims still accurate
- Demo key remains labeled as a demo key
