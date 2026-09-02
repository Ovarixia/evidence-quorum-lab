import type { Identity, Store } from "../types.js";

/**
 * Catalog of synthetic identities and stores.
 * These are lab stand-ins, not connectors to real vendors.
 */
export const IDENTITIES: Record<string, Identity> = {
  "idp-service": {
    id: "idp-service",
    role: "IdP service principal",
    description: "Writes native privilege-grant audit events.",
  },
  "idp-superadmin": {
    id: "idp-superadmin",
    role: "IdP super-admin",
    description: "Can delete or suppress IdP audit records.",
  },
  "sso-provisioner": {
    id: "sso-provisioner",
    role: "SSO provisioner bot",
    description: "Opens or updates ITSM tickets when access changes.",
  },
  "itsm-admin": {
    id: "itsm-admin",
    role: "ITSM administrator",
    description: "Can edit or delete change tickets.",
  },
  "siem-ingester": {
    id: "siem-ingester",
    role: "SIEM ingester",
    description: "Copies IAM telemetry into a search index.",
  },
  "siem-admin": {
    id: "siem-admin",
    role: "SIEM administrator",
    description: "Can delete indexed events or close the index.",
  },
  "github-actions": {
    id: "github-actions",
    role: "CI runner",
    description: "Creates git tags and release metadata on deploy.",
  },
  "vcs-org-owner": {
    id: "vcs-org-owner",
    role: "VCS org owner",
    description: "Can force-push, delete tags, and rewrite history.",
  },
  "ci-bot": {
    id: "ci-bot",
    role: "CI push bot",
    description: "Pushes container images to the registry.",
  },
  "registry-admin": {
    id: "registry-admin",
    role: "Registry administrator",
    description: "Can untag or delete image manifests.",
  },
  "kube-apiserver": {
    id: "kube-apiserver",
    role: "Cluster API server",
    description: "Writes admission / audit events for what actually started.",
  },
  "cluster-admin": {
    id: "cluster-admin",
    role: "Cluster administrator",
    description: "Can wipe kube-audit and disable the audit sink.",
  },
  "stripe-api": {
    id: "stripe-api",
    role: "PSP API",
    description: "Records webhook-endpoint and payout-config changes.",
  },
  "psp-account-owner": {
    id: "psp-account-owner",
    role: "PSP account owner",
    description: "Can alter PSP audit retention or account access.",
  },
  "payments-engineer": {
    id: "payments-engineer",
    role: "Payments engineer",
    description: "Commits payment-config changes to git.",
  },
  "finance-ops": {
    id: "finance-ops",
    role: "Finance operations",
    description: "Files the change ticket for payment configuration.",
  },
  "canary-placer": {
    id: "canary-placer",
    role: "Lab canary placer",
    description: "Writes nonce canaries; not an actor on the critical action.",
  },
};

export const STORES: Record<string, Store> = {
  "idp-audit-log": {
    id: "idp-audit-log",
    kind: "audit-log",
    location: "lab://idp/audit/privilege-grants",
  },
  "itsm-tickets": {
    id: "itsm-tickets",
    kind: "itsm",
    location: "lab://itsm/changes",
  },
  "siem-index": {
    id: "siem-index",
    kind: "siem",
    location: "lab://siem/indexes/iam",
  },
  "git-deploy": {
    id: "git-deploy",
    kind: "vcs",
    location: "lab://git/org/app/releases",
  },
  "oci-registry": {
    id: "oci-registry",
    kind: "registry",
    location: "lab://oci/prod/app",
  },
  "cluster-audit": {
    id: "cluster-audit",
    kind: "runtime-audit",
    location: "lab://cluster/audit/admission",
  },
  "psp-audit": {
    id: "psp-audit",
    kind: "psp-audit",
    location: "lab://psp/audit/config",
  },
  "git-payments": {
    id: "git-payments",
    kind: "vcs",
    location: "lab://git/org/payments-config",
  },
  "canary-worm": {
    id: "canary-worm",
    kind: "canary-witness",
    location: "lab://object-lock/eq-canaries",
  },
};

export function requireStore(id: string): Store {
  const store = STORES[id];
  if (!store) throw new Error(`unknown store: ${id}`);
  return store;
}

export function requireIdentity(id: string): Identity {
  const identity = IDENTITIES[id];
  if (!identity) throw new Error(`unknown identity: ${id}`);
  return identity;
}

export function storeMap(): Map<string, Store> {
  return new Map(Object.entries(STORES));
}
