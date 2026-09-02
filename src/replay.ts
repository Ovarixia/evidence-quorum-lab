import fs from "node:fs";
import path from "node:path";
import { canaryLabel, pathLabel } from "./canary.js";
import { IDENTITIES, STORES } from "./model/catalog.js";
import { ACTIONS } from "./model/scenarios.js";
import { tenantsDir } from "./paths.js";
import { derivedNonce, type ActionView } from "./receipt.js";
import type {
  CanaryObservation,
  CriticalAction,
  EvidencePath,
  PathObservation,
  SensorStatus,
  TenantFixture,
} from "./types.js";

interface PlacedRecord {
  key: string;
  storeId: string;
  kind: "path" | "canary";
  id: string;
  nonce?: string;
}

interface MutableStore {
  reachable: boolean;
  records: Map<string, PlacedRecord>;
}

function cloneAction(action: CriticalAction, aliases: Record<string, string>): CriticalAction {
  const alias = (id: string) => aliases[id] ?? id;
  return {
    ...action,
    paths: action.paths.map((path) => ({
      ...path,
      writerIdentityId: alias(path.writerIdentityId),
      erasers: path.erasers.map(alias),
    })),
    canaries: action.canaries.map((canary) => ({
      ...canary,
      placerIdentityId: alias(canary.placerIdentityId),
      erasers: canary.erasers.map(alias),
    })),
  };
}

function applyAliasesToCatalog(aliases: Record<string, string>): void {
  for (const [from, to] of Object.entries(aliases)) {
    if (!IDENTITIES[to] && IDENTITIES[from]) {
      const source = IDENTITIES[from];
      IDENTITIES[to] = {
        id: to,
        role: `Collapsed role (${from} → ${to})`,
        description: `Lab alias: ${source.description}`,
      };
    }
  }
}

export function loadTenant(id: string): TenantFixture {
  const filePath = path.join(tenantsDir, `${id}.json`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`tenant fixture not found: ${filePath}`);
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as TenantFixture;
}

const DEMO_ORDER = [
  "synth-acme-healthy",
  "synth-acme-degraded",
  "synth-acme-unknown",
  "synth-acme-collapsed",
];

export function listTenantIds(): string[] {
  const ids = fs
    .readdirSync(tenantsDir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => name.replace(/\.json$/, ""));
  const rank = (id: string) => {
    const index = DEMO_ORDER.indexOf(id);
    return index === -1 ? DEMO_ORDER.length : index;
  };
  return ids.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

function sensorFor(
  store: MutableStore,
  record: PlacedRecord | undefined,
): SensorStatus {
  if (!store.reachable) return "unreachable";
  return record ? "present" : "missing";
}

/**
 * Replay one disposable tenant:
 *   1. clone scenarios (optional identity aliases)
 *   2. write evidence + canary nonces into in-memory stores
 *   3. apply fixture faults (missing / unreachable)
 *   4. observe — unreachable stays unreachable
 */
export function replayTenant(tenant: TenantFixture): ActionView[] {
  const aliases = tenant.identityAliases ?? {};
  applyAliasesToCatalog(aliases);

  const stores = new Map<string, MutableStore>();
  for (const store of Object.values(STORES)) {
    stores.set(store.id, { reachable: true, records: new Map() });
  }

  const actions = ACTIONS.map((action) => cloneAction(action, aliases));
  const seed = tenant.seed;

  const placePath = (path: EvidencePath) => {
    const store = stores.get(path.storeId);
    if (!store) throw new Error(`unknown store ${path.storeId}`);
    const key = pathLabel(path);
    store.records.set(key, {
      key,
      storeId: path.storeId,
      kind: "path",
      id: path.id,
    });
  };

  const placeCanary = (action: CriticalAction) => {
    for (const spec of action.canaries) {
      const store = stores.get(spec.storeId);
      if (!store) throw new Error(`unknown canary store ${spec.storeId}`);
      const key = canaryLabel(spec);
      store.records.set(key, {
        key,
        storeId: spec.storeId,
        kind: "canary",
        id: spec.id,
        nonce: derivedNonce(seed, key),
      });
    }
  };

  for (const action of actions) {
    for (const path of action.paths) placePath(path);
    placeCanary(action);
  }

  for (const fault of tenant.faults ?? []) {
    if (fault.kind === "path") {
      const path = actions.flatMap((a) => a.paths).find((p) => p.id === fault.id);
      if (!path) throw new Error(`fault references unknown path ${fault.id}`);
      const store = stores.get(path.storeId);
      if (!store) throw new Error(`unknown store ${path.storeId}`);
      if (fault.status === "unreachable") {
        store.reachable = false;
      } else {
        store.records.delete(pathLabel(path));
      }
    } else {
      const spec = actions
        .flatMap((a) => a.canaries)
        .find((c) => c.id === fault.id);
      if (!spec) throw new Error(`fault references unknown canary ${fault.id}`);
      const store = stores.get(spec.storeId);
      if (!store) throw new Error(`unknown store ${spec.storeId}`);
      if (fault.status === "unreachable") {
        store.reachable = false;
      } else {
        store.records.delete(canaryLabel(spec));
      }
    }
  }

  return actions.map((action) => {
    const pathObservations: PathObservation[] = action.paths.map((path) => {
      const store = stores.get(path.storeId);
      if (!store) throw new Error(`unknown store ${path.storeId}`);
      const record = store.records.get(pathLabel(path));
      return { pathId: path.id, status: sensorFor(store, record) };
    });
    const canaryObservations: CanaryObservation[] = action.canaries.map(
      (spec) => {
        const store = stores.get(spec.storeId);
        if (!store) throw new Error(`unknown store ${spec.storeId}`);
        const record = store.records.get(canaryLabel(spec));
        return {
          canaryId: spec.id,
          nonce: record?.nonce ?? derivedNonce(seed, canaryLabel(spec)),
          status: sensorFor(store, record),
        };
      },
    );
    return { action, pathObservations, canaryObservations };
  });
}
