import { PERFORMANCE_BUDGETS, type PerformanceBudgets } from "./uiFoundationContracts";

export type SearchOption = { id: string; label: string; authorized: boolean };
export type PerformanceEvidence = {
  shellReadyMilliseconds: number[];
  feedbackMilliseconds: number[];
  longTasksMilliseconds: number[];
  largeDataReadyMilliseconds: number[];
  largeDataDomElements: number;
  commandSearchMilliseconds: number[];
  bundle: {
    javascriptGzipBytes: number;
    cssGzipBytes: number;
    combinedGzipBytes: number;
  };
};

function boundedInteger(value: number, fallback: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.trunc(value)));
}

export function boundedOperationalPage<T>(rows: readonly T[], offset: number, limit: number) {
  const boundedOffset = boundedInteger(offset, 0, 0, rows.length);
  const boundedLimit = boundedInteger(
    limit,
    1,
    1,
    PERFORMANCE_BUDGETS.largeData.renderedPageSize,
  );
  const data = rows.slice(boundedOffset, boundedOffset + boundedLimit);

  return {
    data,
    limit: boundedLimit,
    offset: boundedOffset,
    returned: data.length,
    total: rows.length,
  };
}

export function boundedPermissionedSearch(options: readonly SearchOption[], query: string): SearchOption[] {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  return options
    .filter(({ authorized, id, label }) => authorized && (
      normalizedQuery.length === 0
      || id.toLocaleLowerCase().includes(normalizedQuery)
      || label.toLocaleLowerCase().includes(normalizedQuery)
    ))
    .slice(0, PERFORMANCE_BUDGETS.commandSearch.resultLimit);
}

export function percentile(values: readonly number[], quantile: number): number {
  if (values.length === 0 || values.some((value) => !Number.isFinite(value))) {
    return Number.NaN;
  }

  const sorted = [...values].sort((left, right) => left - right);
  const boundedQuantile = Number.isFinite(quantile)
    ? Math.min(1, Math.max(0, quantile))
    : 1;
  const nearestRank = Math.max(1, Math.ceil(boundedQuantile * sorted.length));
  return sorted[nearestRank - 1] ?? Number.NaN;
}

export function validatePerformanceEvidence(
  evidence: PerformanceEvidence,
  budgets: PerformanceBudgets,
): string[] {
  const issues: string[] = [];

  const validateSamples = (
    field: string,
    values: readonly number[],
    maximum: number,
    minimumCount = 1,
    overBudgetLabel = field,
  ) => {
    if (values.length < minimumCount) {
      issues.push(`requires at least ${minimumCount} ${field} samples`);
      return;
    }
    if (values.some((value) => !Number.isFinite(value) || value < 0)) {
      issues.push(`${overBudgetLabel} contains a non-finite or negative measurement`);
      return;
    }
    const p95 = percentile(values, 0.95);
    if (p95 > maximum) {
      issues.push(`${overBudgetLabel} p95 ${p95}ms exceeds ${maximum}ms`);
    }
  };

  validateSamples(
    "shellReadyMilliseconds",
    evidence.shellReadyMilliseconds,
    budgets.localShellReadyP95Milliseconds,
    20,
  );
  validateSamples(
    "feedbackMilliseconds",
    evidence.feedbackMilliseconds,
    budgets.localFeedbackP95Milliseconds,
    1,
    "feedback",
  );
  validateSamples(
    "largeDataReadyMilliseconds",
    evidence.largeDataReadyMilliseconds,
    budgets.largeData.readyP95Milliseconds,
    1,
    "large data",
  );
  validateSamples(
    "commandSearchMilliseconds",
    evidence.commandSearchMilliseconds,
    budgets.commandSearch.readyP95Milliseconds,
    1,
    "command search",
  );

  if (evidence.longTasksMilliseconds.some((value) => !Number.isFinite(value) || value < 0)) {
    issues.push("long task evidence contains a non-finite or negative measurement");
  } else if (evidence.longTasksMilliseconds.some((value) => value >= budgets.longTaskMaximumMilliseconds)) {
    issues.push(`owned long task reached the prohibited ${budgets.longTaskMaximumMilliseconds}ms threshold`);
  }

  if (!Number.isInteger(evidence.largeDataDomElements)
    || evidence.largeDataDomElements < 0
    || evidence.largeDataDomElements > budgets.largeData.maximumWorkspaceDomElements) {
    issues.push(`large data DOM element count must be an integer from 0 through ${budgets.largeData.maximumWorkspaceDomElements}`);
  }

  const validateBytes = (label: string, value: number, maximum: number) => {
    if (!Number.isFinite(value) || value < 0) {
      issues.push(`${label} gzip bytes must be a finite non-negative number`);
    } else if (value > maximum) {
      issues.push(`${label} gzip bytes ${value} exceeds ${maximum}`);
    }
  };
  validateBytes("JavaScript", evidence.bundle.javascriptGzipBytes, budgets.initialJavaScriptGzipBytes);
  validateBytes("CSS", evidence.bundle.cssGzipBytes, budgets.initialCssGzipBytes);
  validateBytes("combined", evidence.bundle.combinedGzipBytes, budgets.initialCombinedGzipBytes);

  return issues;
}
