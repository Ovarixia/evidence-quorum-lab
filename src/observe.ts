/**
 * Observation classifier.
 *
 * Decision table (first match wins):
 *   1. Any path or canary UNREACHABLE → UNKNOWN
 *   2. Any path or canary MISSING     → DEGRADED
 *   3. Design identity min-cut < declared quorum → DEGRADED
 *   4. Else → HEALTHY
 *
 * Unreachable is never coerced into HEALTHY. A dead sensor is not
 * "all good"; it is "we do not know".
 */

import { cutSatisfies } from "./mincut.js";
import type { CutSize, Observation, SensorStatus } from "./types.js";

export interface ClassifyInput {
  pathStatuses: readonly SensorStatus[];
  canaryStatuses: readonly SensorStatus[];
  designIdentityMinCut: CutSize;
  declaredQuorum: number;
}

export function classifyObservation(input: ClassifyInput): Observation {
  const sensors = [...input.pathStatuses, ...input.canaryStatuses];
  if (sensors.some((status) => status === "unreachable")) {
    return "UNKNOWN";
  }
  if (sensors.some((status) => status === "missing")) {
    return "DEGRADED";
  }
  if (!cutSatisfies(input.designIdentityMinCut, input.declaredQuorum)) {
    return "DEGRADED";
  }
  return "HEALTHY";
}

const RANK: Record<Observation, number> = {
  HEALTHY: 0,
  DEGRADED: 1,
  UNKNOWN: 2,
};

export function worstObservation(
  observations: readonly Observation[],
): Observation {
  if (observations.length === 0) return "UNKNOWN";
  let worst: Observation = "HEALTHY";
  for (const item of observations) {
    if (RANK[item] > RANK[worst]) worst = item;
  }
  return worst;
}
