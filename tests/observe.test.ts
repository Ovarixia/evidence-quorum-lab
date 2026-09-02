import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyObservation, worstObservation } from "../src/observe.ts";

const quorum2 = {
  designIdentityMinCut: { finite: true as const, size: 3, example: ["a", "b", "c"] },
  declaredQuorum: 2,
};

describe("classifyObservation", () => {
  it("is HEALTHY only when every sensor is present and quorum is met", () => {
    assert.equal(
      classifyObservation({
        ...quorum2,
        pathStatuses: ["present", "present", "present"],
        canaryStatuses: ["present"],
      }),
      "HEALTHY",
    );
  });

  it("is DEGRADED when a path is missing", () => {
    assert.equal(
      classifyObservation({
        ...quorum2,
        pathStatuses: ["present", "missing", "present"],
        canaryStatuses: ["present"],
      }),
      "DEGRADED",
    );
  });

  it("is DEGRADED when a canary is missing", () => {
    assert.equal(
      classifyObservation({
        ...quorum2,
        pathStatuses: ["present", "present", "present"],
        canaryStatuses: ["missing"],
      }),
      "DEGRADED",
    );
  });

  it("is DEGRADED when design min-cut is below declared quorum (even if logs look fine)", () => {
    assert.equal(
      classifyObservation({
        pathStatuses: ["present", "present", "present"],
        canaryStatuses: ["present"],
        designIdentityMinCut: {
          finite: true,
          size: 1,
          example: ["platform-superadmin"],
        },
        declaredQuorum: 2,
      }),
      "DEGRADED",
    );
  });

  it("is UNKNOWN when any sensor is unreachable", () => {
    assert.equal(
      classifyObservation({
        ...quorum2,
        pathStatuses: ["present", "unreachable", "present"],
        canaryStatuses: ["present"],
      }),
      "UNKNOWN",
    );
  });

  it("never reports HEALTHY when a sensor is unreachable", () => {
    const statuses = ["present", "missing", "unreachable"] as const;
    for (const path of statuses) {
      for (const canary of statuses) {
        const observation = classifyObservation({
          ...quorum2,
          pathStatuses: [path, "present"],
          canaryStatuses: [canary],
        });
        if (path === "unreachable" || canary === "unreachable") {
          assert.equal(observation, "UNKNOWN");
          assert.notEqual(observation, "HEALTHY");
        }
      }
    }
  });

  it("treats unbounded (WORM) min-cut as satisfying any declared quorum", () => {
    assert.equal(
      classifyObservation({
        pathStatuses: ["present"],
        canaryStatuses: ["present"],
        designIdentityMinCut: { finite: false },
        declaredQuorum: 99,
      }),
      "HEALTHY",
    );
  });
});

describe("worstObservation", () => {
  it("promotes UNKNOWN over DEGRADED over HEALTHY", () => {
    assert.equal(worstObservation(["HEALTHY", "DEGRADED"]), "DEGRADED");
    assert.equal(worstObservation(["DEGRADED", "UNKNOWN"]), "UNKNOWN");
    assert.equal(worstObservation(["HEALTHY"]), "HEALTHY");
    assert.equal(worstObservation([]), "UNKNOWN");
  });
});
