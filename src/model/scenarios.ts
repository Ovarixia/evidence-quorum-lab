import type { CriticalAction } from "../types.js";

/**
 * Three critical actions with explicit writers, stores, and erasers.
 * Paths that look "independent" in a slide deck often share an eraser.
 */

const ADMIN: CriticalAction = {
  id: "admin-privilege-grant",
  name: "Admin privilege grant",
  summary:
    "A user is granted an administrator role in the identity provider.",
  declaredQuorum: 2,
  paths: [
    {
      id: "admin.idp-audit",
      actionId: "admin-privilege-grant",
      storeId: "idp-audit-log",
      writerIdentityId: "idp-service",
      erasers: ["idp-superadmin"],
      description:
        "IdP native audit log of the role assignment, written by the IdP service.",
    },
    {
      id: "admin.itsm",
      actionId: "admin-privilege-grant",
      storeId: "itsm-tickets",
      writerIdentityId: "sso-provisioner",
      erasers: ["itsm-admin"],
      description:
        "ITSM change ticket opened (or updated) when the grant is requested or applied.",
    },
    {
      id: "admin.siem",
      actionId: "admin-privilege-grant",
      storeId: "siem-index",
      writerIdentityId: "siem-ingester",
      erasers: ["siem-admin"],
      description:
        "SIEM copy of the IAM event. Independent storage, distinct eraser — unless identities are collapsed.",
    },
  ],
  canaries: [
    {
      id: "admin.canary",
      actionId: "admin-privilege-grant",
      storeId: "canary-worm",
      placerIdentityId: "canary-placer",
      erasers: [],
      description:
        "HMAC nonce in a WORM witness bucket. No modeled identity can delete it.",
    },
  ],
};

const DEPLOY: CriticalAction = {
  id: "production-deploy",
  name: "Production deploy",
  summary:
    "A production release is tagged, pushed as an image, and admitted to the cluster.",
  declaredQuorum: 2,
  paths: [
    {
      id: "deploy.git",
      actionId: "production-deploy",
      storeId: "git-deploy",
      writerIdentityId: "github-actions",
      erasers: ["vcs-org-owner"],
      description: "Git tag / release record written by CI.",
    },
    {
      id: "deploy.registry",
      actionId: "production-deploy",
      storeId: "oci-registry",
      writerIdentityId: "ci-bot",
      erasers: ["registry-admin"],
      description: "Immutable-looking image digest in the container registry.",
    },
    {
      id: "deploy.cluster",
      actionId: "production-deploy",
      storeId: "cluster-audit",
      writerIdentityId: "kube-apiserver",
      erasers: ["cluster-admin"],
      description:
        "Runtime admission audit: what the cluster actually started, not what CI claimed.",
    },
  ],
  canaries: [
    {
      id: "deploy.canary",
      actionId: "production-deploy",
      storeId: "canary-worm",
      placerIdentityId: "canary-placer",
      erasers: [],
      description:
        "HMAC nonce witnessing the image digest at deploy time, WORM storage.",
    },
  ],
};

const PAYMENT: CriticalAction = {
  id: "payment-config-change",
  name: "Payment config change",
  summary:
    "Payout destination or webhook signing secret is changed in the payment stack.",
  declaredQuorum: 2,
  paths: [
    {
      id: "pay.psp",
      actionId: "payment-config-change",
      storeId: "psp-audit",
      writerIdentityId: "stripe-api",
      erasers: ["psp-account-owner"],
      description:
        "PSP-side audit of webhook / payout configuration (external identity).",
    },
    {
      id: "pay.git",
      actionId: "payment-config-change",
      storeId: "git-payments",
      writerIdentityId: "payments-engineer",
      erasers: ["vcs-org-owner"],
      description: "Internal payments-config git history.",
    },
    {
      id: "pay.itsm",
      actionId: "payment-config-change",
      storeId: "itsm-tickets",
      writerIdentityId: "finance-ops",
      erasers: ["itsm-admin"],
      description:
        "Finance change ticket. Shares the ITSM store with the privilege-grant action.",
    },
  ],
  canaries: [
    {
      id: "pay.canary",
      actionId: "payment-config-change",
      storeId: "canary-worm",
      placerIdentityId: "canary-placer",
      erasers: [],
      description:
        "HMAC nonce of the new payout fingerprint in the WORM witness bucket.",
    },
  ],
};

export const ACTIONS: CriticalAction[] = [ADMIN, DEPLOY, PAYMENT];

export function actionById(id: string): CriticalAction {
  const action = ACTIONS.find((item) => item.id === id);
  if (!action) throw new Error(`unknown action: ${id}`);
  return action;
}
