import type { CanarySpec, EvidencePath } from "./types.js";

export interface PlacedCanary {
  spec: CanarySpec;
  nonce: string;
}

export function canaryLabel(spec: CanarySpec): string {
  return `canary:${spec.actionId}:${spec.id}`;
}

export function pathLabel(path: EvidencePath): string {
  return `path:${path.actionId}:${path.id}:${path.storeId}:${path.writerIdentityId}`;
}
