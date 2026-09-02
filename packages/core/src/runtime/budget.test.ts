import { describe, expect, it } from "vitest";
import { MutableBudget } from "./budget.js";

describe("request budgets", () => {
  it("enforces one scan-wide ceiling across probe budgets", () => {
    const scan = new MutableBudget(2);
    const firstProbe = new MutableBudget(2, scan);
    const secondProbe = new MutableBudget(2, scan);

    firstProbe.consume();
    secondProbe.consume();

    expect(firstProbe.available()).toBe(false);
    expect(secondProbe.available()).toBe(false);
    expect(() => firstProbe.consume()).toThrow("request budget exhausted");
    expect(scan.used).toBe(2);
  });
});
