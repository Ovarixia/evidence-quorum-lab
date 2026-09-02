import fs from "node:fs";
import path from "node:path";
import { defaultReceiptDir, demoPublicPemPath } from "./paths.js";
import { buildPayload } from "./receipt.js";
import { listTenantIds, loadTenant, replayTenant } from "./replay.js";
import { receiptToJson, signPayload, verifyReceipt } from "./sign.js";
import type { Observation, TenantFixture } from "./types.js";

export interface LabRunOptions {
  tenantId?: string;
  outDir?: string;
  trustPem?: string;
}

export interface TenantRun {
  tenant: TenantFixture;
  observation: Observation;
  receiptPath: string;
  verified: boolean;
  matchesExpected: boolean;
}

function cutLabel(cut: {
  finite: boolean;
  size: number | null;
}): string {
  if (!cut.finite || cut.size === null) return "unbounded (WORM / no eraser)";
  return String(cut.size);
}

export function formatTenantReport(run: {
  tenant: TenantFixture;
  payload: ReturnType<typeof buildPayload>;
}): string {
  const { tenant, payload } = run;
  const lines: string[] = [];
  lines.push(`tenant     ${tenant.id}  (${tenant.displayName})`);
  lines.push(`seed       ${tenant.seed}`);
  lines.push(
    `overall    ${payload.observation}   expected ${payload.expectedObservation}   ${payload.matchesExpected ? "ok" : "MISMATCH"}`,
  );
  lines.push("");
  for (const scenario of payload.scenarios) {
    lines.push(`  ${scenario.name}  [${scenario.observation}]`);
    lines.push(`    declared quorum (identities): ${scenario.declaredQuorum}`);
    lines.push(
      `    design identity min-cut:     ${cutLabel(scenario.designIdentityMinCut)}${scenario.designIdentityMinCut.finite ? `  {${scenario.designIdentityMinCut.example.join(", ")}}` : ""}`,
    );
    lines.push(
      `    design component min-cut:    ${cutLabel(scenario.designComponentMinCut)}`,
    );
    lines.push(
      `    with canaries (identity):    ${cutLabel(scenario.withCanariesIdentityMinCut)}`,
    );
    lines.push(
      `    intact identity min-cut:     ${cutLabel(scenario.observedIntactIdentityMinCut)}`,
    );
    for (const p of scenario.paths) {
      lines.push(
        `      path  ${p.status.padEnd(12)}  ${p.pathId}  writer=${p.writerIdentityId}  erasers=${p.erasers.join("|") || "∅"}  ${p.location}`,
      );
    }
    for (const c of scenario.canaries) {
      lines.push(
        `      canary ${c.status.padEnd(11)}  ${c.canaryId}  nonce=${c.nonce.slice(0, 12)}…  erasers=${c.erasers.join("|") || "∅"}`,
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}

export function runLab(options: LabRunOptions = {}): {
  runs: TenantRun[];
  ok: boolean;
  stdout: string;
} {
  const outDir = options.outDir ?? defaultReceiptDir();
  fs.mkdirSync(outDir, { recursive: true });
  const ids = options.tenantId ? [options.tenantId] : listTenantIds();
  const trustPem = options.trustPem
    ? fs.readFileSync(options.trustPem, "utf8")
    : fs.readFileSync(demoPublicPemPath, "utf8");

  const runs: TenantRun[] = [];
  const chunks: string[] = [];
  chunks.push("Evidence Quorum + Audit Contract Lab");
  chunks.push("Synthetic tenants only. Not a legal attestation.");
  chunks.push("");

  let ok = true;
  for (const id of ids) {
    const tenant = loadTenant(id);
    const views = replayTenant(tenant);
    const payload = buildPayload(tenant, views);
    const signed = signPayload(payload);
    const receiptPath = path.join(outDir, `${tenant.id}.receipt.json`);
    fs.writeFileSync(receiptPath, receiptToJson(signed));
    const verified = verifyReceipt(signed, trustPem);
    if (!verified.ok || !payload.matchesExpected) ok = false;
    runs.push({
      tenant,
      observation: payload.observation,
      receiptPath,
      verified: verified.ok,
      matchesExpected: payload.matchesExpected,
    });
    chunks.push(formatTenantReport({ tenant, payload }));
    chunks.push(
      `  receipt   ${receiptPath}  verify=${verified.ok ? "VALID" : "INVALID"}`,
    );
    if (!verified.ok) {
      for (const issue of verified.issues) {
        chunks.push(`           ! ${issue.code}: ${issue.message}`);
      }
    }
    chunks.push("");
  }

  chunks.push("What a receipt proves");
  chunks.push(
    "  • Ed25519 signature over canonical JSON of this lab run (seed-locked).",
  );
  chunks.push(
    "  • Self-consistent min-cut and HEALTHY|DEGRADED|UNKNOWN classification.",
  );
  chunks.push("What it does not prove");
  for (const claim of [
    "live production evidence",
    "legal/compliance attestation",
    "trust in the demo key unless you pin --trust",
  ]) {
    chunks.push(`  • ${claim}`);
  }
  chunks.push("");
  chunks.push(
    `Verify: npx tsx src/cli.ts verify ${runs[0]?.receiptPath ?? "receipts/<tenant>.receipt.json"} --trust fixtures/keys/demo-ed25519.pub.pem`,
  );

  return { runs, ok, stdout: chunks.join("\n") };
}
