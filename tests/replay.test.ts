import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { loadTenant, replayTenant } from "../src/replay.ts";
import { buildPayload } from "../src/receipt.ts";
import { parseReceipt, signPayload, verifyReceipt } from "../src/sign.ts";
import { demoPublicPemPath } from "../src/paths.ts";
import { canonicalize } from "../src/canon.ts";
import fs from "node:fs";

const trustPem = fs.readFileSync(demoPublicPemPath, "utf8");

describe("synthetic tenant replay", () => {
  it("classifies the healthy tenant as HEALTHY with identity min-cut 3", () => {
    const tenant = loadTenant("synth-acme-healthy");
    const payload = buildPayload(tenant, replayTenant(tenant));
    assert.equal(payload.observation, "HEALTHY");
    const admin = payload.scenarios.find((s) => s.actionId === "admin-privilege-grant");
    assert.ok(admin);
    assert.equal(admin.observation, "HEALTHY");
    assert.equal(admin.designIdentityMinCut.finite, true);
    assert.equal(admin.designIdentityMinCut.size, 3);
    assert.equal(admin.withCanariesIdentityMinCut.finite, false);
  });

  it("classifies wiped SIEM as DEGRADED, not HEALTHY", () => {
    const tenant = loadTenant("synth-acme-degraded");
    const payload = buildPayload(tenant, replayTenant(tenant));
    assert.equal(payload.observation, "DEGRADED");
    const admin = payload.scenarios.find((s) => s.actionId === "admin-privilege-grant");
    assert.ok(admin);
    const siem = admin.paths.find((p) => p.pathId === "admin.siem");
    assert.equal(siem?.status, "missing");
  });

  it("classifies an unreachable cluster audit sink as UNKNOWN", () => {
    const tenant = loadTenant("synth-acme-unknown");
    const payload = buildPayload(tenant, replayTenant(tenant));
    assert.equal(payload.observation, "UNKNOWN");
    const deploy = payload.scenarios.find((s) => s.actionId === "production-deploy");
    assert.ok(deploy);
    assert.equal(deploy.observation, "UNKNOWN");
    const cluster = deploy.paths.find((p) => p.pathId === "deploy.cluster");
    assert.equal(cluster?.status, "unreachable");
  });

  it("treats collapsed IdP/SIEM/ITSM admins as DEGRADED (quorum fail, logs still present)", () => {
    const tenant = loadTenant("synth-acme-collapsed");
    const payload = buildPayload(tenant, replayTenant(tenant));
    assert.equal(payload.observation, "DEGRADED");
    const admin = payload.scenarios.find((s) => s.actionId === "admin-privilege-grant");
    assert.ok(admin);
    assert.ok(admin.paths.every((p) => p.status === "present"));
    assert.equal(admin.designIdentityMinCut.size, 1);
    assert.deepEqual(admin.designIdentityMinCut.example, ["platform-superadmin"]);
  });

  it("is deterministic for a given seed", () => {
    const tenant = loadTenant("synth-acme-healthy");
    const a = buildPayload(tenant, replayTenant(tenant));
    const b = buildPayload(tenant, replayTenant(tenant));
    assert.equal(
      a.scenarios[0]?.canaries[0]?.nonce,
      b.scenarios[0]?.canaries[0]?.nonce,
    );
    assert.equal(a.issuedAt, b.issuedAt);
  });
});

describe("signed coverage receipt", () => {
  it("signs and verifies a healthy run", () => {
    const tenant = loadTenant("synth-acme-healthy");
    const receipt = signPayload(buildPayload(tenant, replayTenant(tenant)));
    const result = verifyReceipt(receipt, trustPem);
    assert.equal(result.ok, true, JSON.stringify(result.issues));
  });

  it("rejects a tampered observation", () => {
    const tenant = loadTenant("synth-acme-degraded");
    const receipt = signPayload(buildPayload(tenant, replayTenant(tenant)));
    receipt.payload.observation = "HEALTHY";
    const result = verifyReceipt(receipt, trustPem);
    assert.equal(result.ok, false);
    assert.ok(result.issues.some((i) => i.code === "signature" || i.code === "hash" || i.code === "observation"));
  });

  it("round-trips JSON", () => {
    const tenant = loadTenant("synth-acme-healthy");
    const receipt = signPayload(buildPayload(tenant, replayTenant(tenant)));
    const again = parseReceipt(JSON.stringify(receipt));
    assert.equal(verifyReceipt(again, trustPem).ok, true);
  });

  it("verifies a receipt after canonical key-sorted round-trip", () => {
    const tenant = loadTenant("synth-acme-healthy");
    const receipt = signPayload(buildPayload(tenant, replayTenant(tenant)));
    const again = parseReceipt(canonicalize(receipt));
    const result = verifyReceipt(again, trustPem);
    assert.equal(result.ok, true, JSON.stringify(result.issues));
  });
});
