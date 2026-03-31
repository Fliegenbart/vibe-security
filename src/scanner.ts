import type { Scanner, ScanContext, ScanResult, FrameworkInfo } from "./types.js";
import { getProjectFiles } from "./utils.js";
import { detectFramework } from "./detectors/frameworks.js";
import { authScanner } from "./scanners/auth.js";
import { injectionScanner } from "./scanners/injection.js";
import { configScanner } from "./scanners/config.js";

const SCANNERS: Scanner[] = [authScanner, injectionScanner, configScanner];

export interface ScanReport {
  framework: FrameworkInfo;
  results: ScanResult[];
}

export async function runScan(rootDir: string): Promise<ScanReport> {
  const framework = await detectFramework(rootDir);
  const files = await getProjectFiles(rootDir);

  const ctx: ScanContext = { rootDir, files, framework };

  // Run all scanners in parallel
  const results = await Promise.all(SCANNERS.map((s) => s.scan(ctx)));

  return { framework, results };
}
