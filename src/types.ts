/**
 * Shared types for the Evidence Quorum lab.
 *
 * Keep this file boring: it is the audit contract the rest of the code
 * implements. No hidden defaults that upgrade UNKNOWN to HEALTHY.
 */

export type Observation = "HEALTHY" | "DEGRADED" | "UNKNOWN";

export type SensorStatus = "present" | "missing" | "unreachable";

export type StoreKind =
  | "audit-log"
  | "siem"
  | "vcs"
  | "registry"
  | "runtime-audit"
  | "itsm"
  | "psp-audit"
  | "canary-witness";

export interface Identity {
  id: string;
  role: string;
  description: string;
}

export interface Store {
  id: string;
  kind: StoreKind;
  /** Where the evidence lives, as a lab URI (not a live connector). */
  location: string;
  /**
   * Stores that share fate (same bucket, same index, same disk) MUST
   * share a correlation group. The component min-cut hits the group once.
   */
  correlationGroup?: string;
}

export interface EvidencePath {
  id: string;
  actionId: string;
  storeId: string;
  writerIdentityId: string;
  /**
   * Identities that can erase this path. Empty means no modeled identity
   * can delete it (WORM / object-lock / off-identity witness).
   */
  erasers: string[];
  description: string;
}

export interface CanarySpec {
  id: string;
  actionId: string;
  storeId: string;
  placerIdentityId: string;
  erasers: string[];
  description: string;
}

export interface CriticalAction {
  id: string;
  name: string;
  summary: string;
  /** Minimum independent identities the design claims to require. */
  declaredQuorum: number;
  paths: EvidencePath[];
  canaries: CanarySpec[];
}

export type CutSize =
  | { finite: true; size: number; example: string[] }
  | { finite: false };

export interface PathObservation {
  pathId: string;
  status: SensorStatus;
}

export interface CanaryObservation {
  canaryId: string;
  nonce: string;
  status: SensorStatus;
}

export interface Fault {
  kind: "path" | "canary";
  id: string;
  status: "missing" | "unreachable";
}

export interface TenantFixture {
  id: string;
  seed: string;
  displayName: string;
  expectedObservation: Observation;
  /**
   * Rewrite identity ids after load. Used to demonstrate collapsed
   * admin roles (several "independent" paths, one human).
   */
  identityAliases?: Record<string, string>;
  faults?: Fault[];
}

export const RECEIPT_SPEC = "evidence-quorum-receipt/v1" as const;

export const NON_CLAIMS = [
  "Not a legal attestation, notary record, or court-admissible proof.",
  "Not a SOC 2 / ISO 27001 / PCI control or auditor letter.",
  "Not connected to a live SIEM, IdP, PSP, or production cluster.",
  "Not proof that an action occurred outside this synthetic lab.",
  "Signature proves integrity of this JSON, not trustworthiness of the signer unless you pin --trust.",
] as const;
