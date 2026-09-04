import { hmacHex } from "./crypto.js";
import { canaryLabel } from "./canary.js";
import {
  componentSets,
  cutSatisfies,
  cutToJson,
  identitySets,
  minHittingSet,
} from "./mincut.js";
import { storeMap } from "./model/catalog.js";
import { ACTIONS } from "./model/scenarios.js";
import { classifyObservation, worstObservation } from "./observe.js";
import type {
  CanaryObservation,
  CriticalAction,
  CutSize,
  Observation,
  PathObservation,
  TenantFixture,
} from "./types.js";
import { NON_CLAIMS, RECEIPT_SPEC } from "./types.js";

export const LAB_EPOCH = "2026-09-02T00:00:00.000Z";

export interface ScenarioResult {
  actionId: string;
  name: string;
  summary: string;
  declaredQuorum: number;
  observation: Observation;
  designIdentityMinCut: ReturnType<typeof cutToJson>;
  designComponentMinCut: ReturnType<typeof cutToJson>;
  withCanariesIdentityMinCut: ReturnType<typeof cutToJson>;
  withCanariesComponentMinCut: ReturnType<typeof cutToJson>;
  observedIntactIdentityMinCut: ReturnType<typeof cutToJson>;
  quorumMet: boolean;
  paths: Array<
    PathObservation & {
      storeId: string;
      writerIdentityId: string;
      erasers: string[];
      location: string;
      description: string;
    }
  >;
  canaries: Array<
    CanaryObservation & {
      storeId: string;
      erasers: string[];
      description: string;
    }
  >;
}

export interface ReceiptPayload {
  spec: typeof RECEIPT_SPEC;
  lab: "evidence-quorum-lab";
  clock: "seed-derived";
  issuedAt: string;
  tenant: {
    id: string;
    seed: string;
    displayName: string;
  };
  observation: Observation;
  expectedObservation: Observation;
  matchesExpected: boolean;
  scenarios: ScenarioResult[];
  nonClaims: typeof NON_CLAIMS;
}

export interface SignedReceipt {
  payload: ReceiptPayload;
  payloadSha256: string;
  signature: {
    alg: "Ed25519";
    keyId: string;
    publicKeyPem: string;
    publicKeySha256: string;
    sig: string;
  };
}

export interface ActionView {
  action: CriticalAction;
  pathObservations: PathObservation[];
  canaryObservations: CanaryObservation[];
}

function intactIdentityCut(
  action: CriticalAction,
  pathObservations: readonly PathObservation[],
): CutSize {
  const presentIds = new Set(
    pathObservations.filter((p) => p.status === "present").map((p) => p.pathId),
  );
  const intact = action.paths.filter((p) => presentIds.has(p.id));
  return minHittingSet(identitySets(intact));
}

export function evaluateAction(view: ActionView): ScenarioResult {
  const { action, pathObservations, canaryObservations } = view;
  const stores = storeMap();

  const designIdentity = minHittingSet(identitySets(action.paths));
  const designComponent = minHittingSet(componentSets(action.paths, stores));
  const withCanariesIdentity = minHittingSet([
    ...identitySets(action.paths),
    ...action.canaries.map((c) => [...c.erasers]),
  ]);
  const withCanariesComponent = minHittingSet([
    ...componentSets(action.paths, stores),
    ...action.canaries.map((c) => {
      const store = stores.get(c.storeId);
      if (!store) throw new Error(`unknown canary store ${c.storeId}`);
      return [store.correlationGroup ?? store.id];
    }),
  ]);

  const observation = classifyObservation({
    pathStatuses: pathObservations.map((p) => p.status),
    canaryStatuses: canaryObservations.map((c) => c.status),
    designIdentityMinCut: designIdentity,
    declaredQuorum: action.declaredQuorum,
  });

  return {
    actionId: action.id,
    name: action.name,
    summary: action.summary,
    declaredQuorum: action.declaredQuorum,
    observation,
    designIdentityMinCut: cutToJson(designIdentity),
    designComponentMinCut: cutToJson(designComponent),
    withCanariesIdentityMinCut: cutToJson(withCanariesIdentity),
    withCanariesComponentMinCut: cutToJson(withCanariesComponent),
    observedIntactIdentityMinCut: cutToJson(
      intactIdentityCut(action, pathObservations),
    ),
    quorumMet: cutSatisfies(designIdentity, action.declaredQuorum),
    paths: action.paths.map((path) => {
      const obs = pathObservations.find((p) => p.pathId === path.id);
      const store = stores.get(path.storeId);
      if (!obs) throw new Error(`missing observation for ${path.id}`);
      if (!store) throw new Error(`unknown store ${path.storeId}`);
      return {
        pathId: path.id,
        status: obs.status,
        storeId: path.storeId,
        writerIdentityId: path.writerIdentityId,
        erasers: [...path.erasers],
        location: store.location,
        description: path.description,
      };
    }),
    canaries: action.canaries.map((canary) => {
      const obs = canaryObservations.find((c) => c.canaryId === canary.id);
      if (!obs) throw new Error(`missing canary observation for ${canary.id}`);
      return {
        canaryId: canary.id,
        nonce: obs.nonce,
        status: obs.status,
        storeId: canary.storeId,
        erasers: [...canary.erasers],
        description: canary.description,
      };
    }),
  };
}

export function buildPayload(
  tenant: TenantFixture,
  views: ActionView[],
): ReceiptPayload {
  const scenarios = views.map(evaluateAction);
  const observation = worstObservation(scenarios.map((s) => s.observation));
  return {
    spec: RECEIPT_SPEC,
    lab: "evidence-quorum-lab",
    clock: "seed-derived",
    issuedAt: LAB_EPOCH,
    tenant: {
      id: tenant.id,
      seed: tenant.seed,
      displayName: tenant.displayName,
    },
    observation,
    expectedObservation: tenant.expectedObservation,
    matchesExpected: observation === tenant.expectedObservation,
    scenarios,
    nonClaims: NON_CLAIMS,
  };
}

/** Recompute min-cuts and observation from the embedded graph; used by verify. */
export function recomputeFromPayload(payload: ReceiptPayload): {
  observation: Observation;
  scenarios: ScenarioResult[];
} {
  const views: ActionView[] = payload.scenarios.map((scenario) => {
    const action = ACTIONS.find((a) => a.id === scenario.actionId);
    if (!action) {
      throw new Error(`receipt references unknown action ${scenario.actionId}`);
    }
    return {
      action: {
        ...action,
        paths: action.paths.map((path) => {
          const embedded = scenario.paths.find((p) => p.pathId === path.id);
          return embedded
            ? { ...path, erasers: [...embedded.erasers] }
            : path;
        }),
        canaries: action.canaries.map((canary) => {
          const embedded = scenario.canaries.find(
            (c) => c.canaryId === canary.id,
          );
          return embedded
            ? { ...canary, erasers: [...embedded.erasers] }
            : canary;
        }),
      },
      pathObservations: scenario.paths.map((p) => ({
        pathId: p.pathId,
        status: p.status,
      })),
      canaryObservations: action.canaries.map((canary) => {
        const embedded = scenario.canaries.find((item) => item.canaryId === canary.id);
        if (!embedded) throw new Error(`missing canary observation for ${canary.id}`);
        return {
          canaryId: canary.id,
          nonce: derivedNonce(payload.tenant.seed, canaryLabel(canary)),
          status: embedded.status,
        };
      }),
    };
  });

  const scenarios = views.map(evaluateAction);
  return {
    observation: worstObservation(scenarios.map((s) => s.observation)),
    scenarios,
  };
}

export function derivedNonce(seed: string, label: string): string {
  return hmacHex(seed, label, 16);
}
