#!/usr/bin/env node
import fs from "node:fs";
import { runLab } from "./lab.js";
import { demoPublicPemPath } from "./paths.js";
import { listTenantIds } from "./replay.js";
import { parseReceipt, verifyReceipt } from "./sign.js";

function printHelp(): void {
  process.stdout.write(`Evidence Quorum Lab — synthetic audit-contract runner

Usage:
  eq-lab run [--tenant ID] [--out-dir DIR] [--trust PEM]
  eq-lab verify <receipt.json> [--trust PEM]
  eq-lab list-tenants
  eq-lab help

One-command demo (from repo root):
  npm start

Tenants are disposable JSON fixtures under fixtures/tenants/.
The demo Ed25519 key is committed on purpose and is NOT a trust root.
`);
}

function takeFlag(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  args.splice(index, 2);
  return value;
}

function main(argv: string[]): number {
  const [command = "help", ...rest] = argv;

  if (command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return 0;
  }

  if (command === "list-tenants") {
    for (const id of listTenantIds()) process.stdout.write(`${id}\n`);
    return 0;
  }

  if (command === "run") {
    const args = [...rest];
    const tenantId = takeFlag(args, "--tenant");
    const outDir = takeFlag(args, "--out-dir");
    const trustPem = takeFlag(args, "--trust");
    if (args.length) {
      process.stderr.write(`unknown arguments: ${args.join(" ")}\n`);
      return 2;
    }
    const result = runLab({ tenantId, outDir, trustPem });
    process.stdout.write(`${result.stdout}\n`);
    return result.ok ? 0 : 1;
  }

  if (command === "verify") {
    const args = [...rest];
    const trust = takeFlag(args, "--trust") ?? demoPublicPemPath;
    const file = args.shift();
    if (!file || args.length) {
      process.stderr.write("usage: eq-lab verify <receipt.json> [--trust PEM]\n");
      return 2;
    }
    const receipt = parseReceipt(fs.readFileSync(file, "utf8"));
    const trustPem = fs.readFileSync(trust, "utf8");
    const result = verifyReceipt(receipt, trustPem);
    if (result.ok) {
      process.stdout.write(
        `VALID  ${file}\n  tenant=${receipt.payload.tenant.id}  observation=${receipt.payload.observation}  sha256=${receipt.payloadSha256}\n`,
      );
      return 0;
    }
    process.stdout.write(`INVALID  ${file}\n`);
    for (const issue of result.issues) {
      process.stdout.write(`  - ${issue.code}: ${issue.message}\n`);
    }
    return 1;
  }

  process.stderr.write(`unknown command: ${command}\n`);
  printHelp();
  return 2;
}

process.exitCode = main(process.argv.slice(2));
