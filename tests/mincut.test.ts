import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { minHittingSet } from "../src/mincut.ts";

describe("minHittingSet", () => {
  it("returns size 0 for no paths", () => {
    const cut = minHittingSet([]);
    assert.equal(cut.finite, true);
    if (cut.finite) assert.equal(cut.size, 0);
  });

  it("counts distinct identities as the cut when each path has one eraser", () => {
    const cut = minHittingSet([["idp"], ["itsm"], ["siem"]]);
    assert.equal(cut.finite, true);
    if (cut.finite) {
      assert.equal(cut.size, 3);
      assert.deepEqual(cut.example.sort(), ["idp", "itsm", "siem"]);
    }
  });

  it("collapses shared identity to cut size 1", () => {
    const cut = minHittingSet([
      ["platform-admin"],
      ["platform-admin"],
      ["platform-admin"],
    ]);
    assert.equal(cut.finite, true);
    if (cut.finite) {
      assert.equal(cut.size, 1);
      assert.deepEqual(cut.example, ["platform-admin"]);
    }
  });

  it("solves OR-erasers as a true hitting set", () => {
    // Path A: only alice. Path B: alice OR bob. Path C: carol.
    // Min hit: {alice, carol} size 2, not 3.
    const cut = minHittingSet([["alice"], ["alice", "bob"], ["carol"]]);
    assert.equal(cut.finite, true);
    if (cut.finite) {
      assert.equal(cut.size, 2);
      assert.ok(cut.example.includes("carol"));
      assert.ok(cut.example.includes("alice") || cut.example.includes("bob"));
    }
  });

  it("is unbounded when any path has no eraser (WORM)", () => {
    const cut = minHittingSet([["idp"], []]);
    assert.equal(cut.finite, false);
  });
});
