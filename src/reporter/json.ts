import type { ScanResult, FrameworkInfo } from "../types.js";

export interface JsonReport {
  version: string;
  framework: FrameworkInfo;
  totalFiles: number;
  totalFindings: number;
  counts: { critical: number; high: number; medium: number; low: number };
  findings: ScanResult[];
}

export function generateJsonReport(
  results: ScanResult[],
  framework: FrameworkInfo
): JsonReport {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of results) {
    for (const f of r.findings) {
      counts[f.severity]++;
    }
  }

  return {
    version: "1.0.0",
    framework,
    totalFiles: results.reduce((sum, r) => sum + r.filesScanned, 0),
    totalFindings: Object.values(counts).reduce((a, b) => a + b, 0),
    counts,
    findings: results,
  };
}
