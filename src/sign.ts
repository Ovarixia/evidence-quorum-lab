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
  type ReceiptPayload,
  type SignedReceipt,
} from "./receipt.js";

export type { SignedReceipt } from "./receipt.js";
import { RECEIPT_SPEC } from "./types.js";

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

export function verifyReceipt(
  receipt: SignedReceipt,
  trustedPublicKeyPem?: string,
): VerifyResult {
  const issues: VerifyIssue[] = [];
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

  const sigOk = verifyCanonical(
    payload,
    signature.publicKeyPem,
    signature.sig,
  );
  if (!sigOk) {
    issues.push({
      code: "signature",
      message: "Ed25519 signature does not verify over canonical payload",
    });
  }

  if (trustedPublicKeyPem) {
    const pinned = pemFingerprints(trustedPublicKeyPem);
    const embedded = pemFingerprints(signature.publicKeyPem);
    if (pinned !== embedded) {
      issues.push({
        code: "trust",
        message:
          "embedded public key does not match --trust pin (receipt is self-signed by an unexpected key)",
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
      if (again.observation !== scenario.observation) {
        issues.push({
          code: "scenario-observation",
          message: `${scenario.actionId}: ${scenario.observation} != ${again.observation}`,
        });
      }
      if (
        canonicalize(scenario.designIdentityMinCut) !==
        canonicalize(again.designIdentityMinCut)
      ) {
        issues.push({
          code: "mincut",
          message: `${scenario.actionId}: design identity min-cut does not recompute`,
        });
      }
    }
  } catch (err) {
    issues.push({
      code: "recompute",
      message: err instanceof Error ? err.message : String(err),
    });
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
  const parsed = JSON.parse(raw) as SignedReceipt;
  if (!parsed.payload || !parsed.signature) {
    throw new Error("not a signed coverage receipt");
  }
  return parsed;
}

export function receiptToJson(receipt: SignedReceipt): string {
  return `${canonicalize(receipt)}\n`;
}
