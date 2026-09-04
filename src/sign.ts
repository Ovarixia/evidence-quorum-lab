import { canonicalize } from "./canon.js";
import {
  loadLabKey,
  pemFingerprints,
  sha256Canonical,
  signCanonical,
  verifyCanonical,
} from "./crypto.js";
import { demoKeyPath } from "./paths.js";
import {
  recomputeFromPayload,
  LAB_EPOCH,
  type ReceiptPayload,
  type SignedReceipt,
} from "./receipt.js";
import { ACTIONS } from "./model/scenarios.js";

export type { SignedReceipt } from "./receipt.js";
import { NON_CLAIMS, RECEIPT_SPEC } from "./types.js";

export function signPayload(payload: ReceiptPayload): SignedReceipt {
  const key = loadLabKey(demoKeyPath);
  const sig = signCanonical(payload, key);
  return {
    payload,
    payloadSha256: sha256Canonical(payload),
    signature: {
      alg: "Ed25519",
      keyId: key.keyId,
      publicKeyPem: key.publicKeyPem,
      publicKeySha256: pemFingerprints(key.publicKeyPem),
      sig,
    },
  };
}

export interface VerifyIssue {
  code: string;
  message: string;
}

export interface VerifyResult {
  ok: boolean;
  issues: VerifyIssue[];
}

const OBSERVATIONS = new Set(["HEALTHY", "DEGRADED", "UNKNOWN"]);
const SENSOR_STATUSES = new Set(["present", "missing", "unreachable"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sameIds(actual: string[], expected: string[]): boolean {
  return actual.length === expected.length &&
    new Set(actual).size === actual.length &&
    expected.every((id) => actual.includes(id));
}

function validateReceiptStructure(value: unknown): VerifyIssue[] {
  const issues: VerifyIssue[] = [];
  if (!isRecord(value) || !isRecord(value.payload) || !isRecord(value.signature)) {
    return [{ code: "schema", message: "receipt must contain payload and signature objects" }];
  }
  const payload = value.payload;
  const signature = value.signature;
  if (typeof value.payloadSha256 !== "string" ||
      typeof signature.alg !== "string" ||
      typeof signature.keyId !== "string" ||
      typeof signature.publicKeyPem !== "string" ||
      typeof signature.publicKeySha256 !== "string" ||
      typeof signature.sig !== "string") {
    issues.push({ code: "schema", message: "receipt signature fields must be strings" });
  }
  if (!isRecord(payload.tenant) || typeof payload.tenant.seed !== "string" ||
      !Array.isArray(payload.scenarios) || typeof payload.observation !== "string" ||
      !OBSERVATIONS.has(payload.observation) || typeof payload.expectedObservation !== "string" ||
      !OBSERVATIONS.has(payload.expectedObservation)) {
    issues.push({ code: "schema", message: "receipt payload has invalid tenant, scenarios, or observation fields" });
    return issues;
  }

  const scenarios = payload.scenarios;
  const scenarioIds = scenarios.map((item) => isRecord(item) ? item.actionId : undefined);
  if (scenarioIds.some((id) => typeof id !== "string") ||
      !sameIds(scenarioIds as string[], ACTIONS.map((action) => action.id))) {
    issues.push({
      code: "scenario-set",
      message: "receipt must contain each canonical critical action exactly once",
    });
  }

  for (const item of scenarios) {
    if (!isRecord(item) || typeof item.actionId !== "string") continue;
    const action = ACTIONS.find((candidate) => candidate.id === item.actionId);
    if (!action || !Array.isArray(item.paths) || !Array.isArray(item.canaries)) {
      issues.push({ code: "schema", message: `${item.actionId}: invalid paths or canaries` });
      continue;
    }
    const pathIds = item.paths.map((path) => isRecord(path) ? path.pathId : undefined);
    const canaryIds = item.canaries.map((canary) => isRecord(canary) ? canary.canaryId : undefined);
    if (pathIds.some((id) => typeof id !== "string") ||
        !sameIds(pathIds as string[], action.paths.map((path) => path.id))) {
      issues.push({ code: "path-set", message: `${item.actionId}: paths must match the canonical action exactly` });
    }
    if (canaryIds.some((id) => typeof id !== "string") ||
        !sameIds(canaryIds as string[], action.canaries.map((canary) => canary.id))) {
      issues.push({ code: "canary-set", message: `${item.actionId}: canaries must match the canonical action exactly` });
    }
    const invalidStatus = [...item.paths, ...item.canaries].some(
      (entry) => !isRecord(entry) || typeof entry.status !== "string" || !SENSOR_STATUSES.has(entry.status),
    );
    if (invalidStatus || typeof item.observation !== "string" || !OBSERVATIONS.has(item.observation)) {
      issues.push({ code: "sensor-status", message: `${item.actionId}: invalid observation or sensor status` });
    }
  }
  return issues;
}

function scenarioSecurityProjection(scenario: ReceiptPayload["scenarios"][number]): unknown {
  return {
    actionId: scenario.actionId,
    declaredQuorum: scenario.declaredQuorum,
    observation: scenario.observation,
    designIdentityMinCut: scenario.designIdentityMinCut,
    designComponentMinCut: scenario.designComponentMinCut,
    withCanariesIdentityMinCut: scenario.withCanariesIdentityMinCut,
    withCanariesComponentMinCut: scenario.withCanariesComponentMinCut,
    observedIntactIdentityMinCut: scenario.observedIntactIdentityMinCut,
    quorumMet: scenario.quorumMet,
    canaries: scenario.canaries.map(({ canaryId, nonce, status }) => ({ canaryId, nonce, status })),
  };
}

export function verifyReceipt(
  receipt: SignedReceipt,
  trustedPublicKeyPem?: string,
): VerifyResult {
  const issues = validateReceiptStructure(receipt);
  if (issues.length > 0) return { ok: false, issues };
  const { payload, signature } = receipt;

  if (payload.spec !== RECEIPT_SPEC) {
    issues.push({
      code: "spec",
      message: `unexpected spec ${payload.spec}`,
    });
  }

  if (signature.alg !== "Ed25519") {
    issues.push({
      code: "alg",
      message: `unexpected alg ${signature.alg}`,
    });
  }

  const digest = sha256Canonical(payload);
  if (digest !== receipt.payloadSha256) {
    issues.push({
      code: "hash",
      message: "payloadSha256 does not match canonical SHA-256 of payload",
    });
  }

  try {
    if (!verifyCanonical(payload, signature.publicKeyPem, signature.sig)) {
      issues.push({
        code: "signature",
        message: "Ed25519 signature does not verify over canonical payload",
      });
    }
  } catch {
    issues.push({
      code: "signature",
      message: "embedded public key or signature is malformed",
    });
  }

  try {
    if (pemFingerprints(signature.publicKeyPem) !== signature.publicKeySha256) {
      issues.push({ code: "key-fingerprint", message: "embedded public-key fingerprint is inconsistent" });
    }
  } catch {
    issues.push({ code: "key-fingerprint", message: "embedded public key is malformed" });
  }

  if (trustedPublicKeyPem) {
    try {
      const pinned = pemFingerprints(trustedPublicKeyPem);
      const embedded = pemFingerprints(signature.publicKeyPem);
      if (pinned !== embedded) {
        issues.push({
          code: "trust",
          message:
            "embedded public key does not match --trust pin (receipt is self-signed by an unexpected key)",
        });
      }
    } catch {
      issues.push({
        code: "trust",
        message: "trusted or embedded public key is malformed",
      });
    }
  }

  try {
    const recomputed = recomputeFromPayload(payload);
    if (recomputed.observation !== payload.observation) {
      issues.push({
        code: "observation",
        message: `embedded observation ${payload.observation} != recomputed ${recomputed.observation}`,
      });
    }
    for (const scenario of payload.scenarios) {
      const again = recomputed.scenarios.find(
        (s) => s.actionId === scenario.actionId,
      );
      if (!again) {
        issues.push({
          code: "scenario",
          message: `missing recomputed scenario ${scenario.actionId}`,
        });
        continue;
      }
      if (canonicalize(scenarioSecurityProjection(scenario)) !==
          canonicalize(scenarioSecurityProjection(again))) {
        issues.push({
          code: "scenario-derived",
          message: `${scenario.actionId}: security fields do not fully recompute`,
        });
      }
    }
  } catch (err) {
    issues.push({
      code: "recompute",
      message: err instanceof Error ? err.message : String(err),
    });
  }

  if (payload.lab !== "evidence-quorum-lab" || payload.clock !== "seed-derived" ||
      payload.issuedAt !== LAB_EPOCH || canonicalize(payload.nonClaims) !== canonicalize(NON_CLAIMS)) {
    issues.push({ code: "protocol-metadata", message: "receipt protocol metadata is inconsistent" });
  }
  if (payload.matchesExpected !== (payload.observation === payload.expectedObservation)) {
    issues.push({ code: "matches-expected", message: "matchesExpected does not match the observations" });
  }

  if (payload.observation === "HEALTHY") {
    const anyUnreachable = payload.scenarios.some(
      (s) =>
        s.paths.some((p) => p.status === "unreachable") ||
        s.canaries.some((c) => c.status === "unreachable"),
    );
    if (anyUnreachable) {
      issues.push({
        code: "honest",
        message: "HEALTHY receipt contains unreachable sensors (never all-good)",
      });
    }
  }

  return { ok: issues.length === 0, issues };
}

export function parseReceipt(raw: string): SignedReceipt {
  const parsed: unknown = JSON.parse(raw);
  const issues = validateReceiptStructure(parsed);
  if (issues.length > 0) throw new Error(`not a signed coverage receipt: ${issues[0]?.message}`);
  return parsed as SignedReceipt;
}

export function receiptToJson(receipt: SignedReceipt): string {
  return `${canonicalize(receipt)}\n`;
}
