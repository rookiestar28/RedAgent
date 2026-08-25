import { describe, expect, it } from "vitest";

import { PERFORMANCE_BUDGETS } from "./uiFoundationContracts";
import {
  boundedOperationalPage,
  boundedPermissionedSearch,
  percentile,
  validatePerformanceEvidence,
} from "./uiFoundationPerformance";

describe("compat_126 performance measurement helpers", () => {
  it("bounds an operational page to the frozen 100-row limit", () => {
    const rows = Array.from({ length: 1000 }, (_, index) => ({ id: `row-${index}` }));
    expect(boundedOperationalPage(rows, 0, 500)).toEqual({
      data: rows.slice(0, 100),
      limit: 100,
      offset: 0,
      returned: 100,
      total: 1000,
    });
    expect(boundedOperationalPage(rows, 998.9, -4)).toEqual({
      data: rows.slice(998, 999),
      limit: 1,
      offset: 998,
      returned: 1,
      total: 1000,
    });
  });

  it("filters only authorized options and caps command results at 50", () => {
    const options = Array.from({ length: 1000 }, (_, index) => ({
      id: `route-${index}`,
      label: `Campaign route ${index}`,
      authorized: index % 2 === 0,
    }));
    const results = boundedPermissionedSearch(options, "campaign");

    expect(results).toHaveLength(50);
    expect(results.every(({ authorized }) => authorized)).toBe(true);
    expect(boundedPermissionedSearch(options, "route-998")).toEqual([options[998]]);
    expect(boundedPermissionedSearch(options, "route-999")).toEqual([]);
  });

  it("computes nearest-rank percentiles deterministically", () => {
    const values = [10, 50, 20, 40, 30];
    expect(percentile(values, 0.95)).toBe(50);
    expect(percentile([10, 20, 30, 40], 0.5)).toBe(20);
    expect(values).toEqual([10, 50, 20, 40, 30]);
    expect(percentile([], 0.95)).toBeNaN();
  });

  it("accepts complete evidence exactly at the frozen boundaries", () => {
    expect(validatePerformanceEvidence({
      shellReadyMilliseconds: Array.from({ length: 20 }, () => 1000),
      feedbackMilliseconds: [100],
      longTasksMilliseconds: [49.999],
      largeDataReadyMilliseconds: [250],
      largeDataDomElements: 1500,
      commandSearchMilliseconds: [100],
      bundle: { javascriptGzipBytes: 122880, cssGzipBytes: 12288, combinedGzipBytes: 138240 },
    }, PERFORMANCE_BUDGETS)).toEqual([]);
  });

  it("rejects missing, oversized, or over-budget evidence", () => {
    expect(validatePerformanceEvidence({
      shellReadyMilliseconds: [],
      feedbackMilliseconds: [101],
      longTasksMilliseconds: [50],
      largeDataReadyMilliseconds: [251],
      largeDataDomElements: 1501,
      commandSearchMilliseconds: [101],
      bundle: { javascriptGzipBytes: 122881, cssGzipBytes: 12289, combinedGzipBytes: 138241 },
    }, PERFORMANCE_BUDGETS)).toEqual(expect.arrayContaining([
      expect.stringContaining("shellReadyMilliseconds"),
      expect.stringContaining("feedback"),
      expect.stringContaining("long task"),
      expect.stringContaining("large data"),
      expect.stringContaining("DOM"),
      expect.stringContaining("command search"),
      expect.stringContaining("JavaScript"),
      expect.stringContaining("CSS"),
      expect.stringContaining("combined"),
    ]));
  });

  it("rejects incomplete sample sets and non-finite measurements", () => {
    const issues = validatePerformanceEvidence({
      shellReadyMilliseconds: [999],
      feedbackMilliseconds: [Number.NaN],
      longTasksMilliseconds: [Number.POSITIVE_INFINITY],
      largeDataReadyMilliseconds: [],
      largeDataDomElements: -1,
      commandSearchMilliseconds: [],
      bundle: { javascriptGzipBytes: -1, cssGzipBytes: 0, combinedGzipBytes: 0 },
    }, PERFORMANCE_BUDGETS);

    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining("20 shellReadyMilliseconds"),
      expect.stringContaining("feedback"),
      expect.stringContaining("long task"),
      expect.stringContaining("largeDataReadyMilliseconds"),
      expect.stringContaining("DOM"),
      expect.stringContaining("commandSearchMilliseconds"),
      expect.stringContaining("JavaScript"),
    ]));
  });
});
