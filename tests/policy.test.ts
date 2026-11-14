import assert from "node:assert/strict";
import test from "node:test";
import { evaluateRepositoryScan } from "../packages/policy/src/index.ts";

test("passes a complete scan with advisory findings", () => {
  assert.equal(evaluateRepositoryScan([{ category: "dependency", severity: "critical" }], "complete"), "pass");
});

test("blocks on a high-severity secret even with partial coverage", () => {
  assert.equal(evaluateRepositoryScan([{ category: "secret", severity: "high" }], "incomplete"), "block");
});

test("returns incomplete when there is no blocker and coverage is partial", () => {
  assert.equal(evaluateRepositoryScan([], "incomplete"), "incomplete");
});
