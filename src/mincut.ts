/**
 * Minimum hitting set = min-cut for this lab.
 *
 * Each evidence path is a set of identities (or component keys) that can
 * erase it. An adversary who wants the action to leave *no* trace must
 * hit every set: compromise at least one eraser per path.
 *
 * N is tiny (≤ ~16), so we enumerate subsets. That is deliberate: the
 * algorithm is auditable in a page of code, not a max-flow library.
 */

import type { CutSize, EvidencePath, Store } from "./types.js";

const MAX_UNIVERSE = 20;

export function minHittingSet(sets: readonly (readonly string[])[]): CutSize {
  if (sets.length === 0) {
    return { finite: true, size: 0, example: [] };
  }
  // A path with no erasers cannot be hit → no finite cut.
  if (sets.some((set) => set.length === 0)) {
    return { finite: false };
  }

  const universe = [...new Set(sets.flat())];
  if (universe.length > MAX_UNIVERSE) {
    throw new Error(
      `hitting-set universe too large (${universe.length} > ${MAX_UNIVERSE}); lab graphs must stay small`,
    );
  }

  let best: string[] | null = null;
  const limit = 1 << universe.length;
  for (let mask = 1; mask < limit; mask++) {
    const pick: string[] = [];
    for (let i = 0; i < universe.length; i++) {
      if (mask & (1 << i)) {
        const id = universe[i];
        if (id !== undefined) pick.push(id);
      }
    }
    if (best && pick.length >= best.length) continue;
    const selected = new Set(pick);
    const covers = sets.every((set) => set.some((item) => selected.has(item)));
    if (covers) best = pick;
  }

  if (!best) {
    return { finite: false };
  }
  return { finite: true, size: best.length, example: best.sort() };
}

export function identitySets(paths: readonly EvidencePath[]): string[][] {
  return paths.map((path) => [...path.erasers]);
}

export function componentKey(store: Store): string {
  return store.correlationGroup ?? store.id;
}

export function componentSets(
  paths: readonly EvidencePath[],
  stores: ReadonlyMap<string, Store>,
): string[][] {
  return paths.map((path) => {
    const store = stores.get(path.storeId);
    if (!store) {
      throw new Error(`unknown store ${path.storeId} on path ${path.id}`);
    }
    return [componentKey(store)];
  });
}

export function cutToJson(cut: CutSize): {
  finite: boolean;
  size: number | null;
  example: string[];
} {
  if (!cut.finite) {
    return { finite: false, size: null, example: [] };
  }
  return { finite: true, size: cut.size, example: cut.example };
}

export function cutSatisfies(cut: CutSize, declaredQuorum: number): boolean {
  if (!cut.finite) return true;
  return cut.size >= declaredQuorum;
}
