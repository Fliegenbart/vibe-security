import chalk from "chalk";
import type { Finding, ScanResult, Severity } from "../types.js";

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: chalk.bgRed.white.bold(" CRITICAL "),
  high: chalk.red.bold("    HIGH  "),
  medium: chalk.yellow.bold("  MEDIUM  "),
  low: chalk.blue.bold("     LOW  "),
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export function printHeader(): void {
  console.log();
  console.log(chalk.bold("  vibesafe") + chalk.dim(" v1.0.0") + chalk.dim(" — Security scanner for AI-generated projects"));
  console.log();
}

export function printFramework(name: string, type: string): void {
  console.log(chalk.dim("  Detected: ") + chalk.cyan(name) + chalk.dim(` (${type})`));
  console.log();
}

export function printResults(results: ScanResult[]): void {
  const allFindings = results
    .flatMap((r) => r.findings)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const totalFiles = results.reduce((sum, r) => sum + r.filesScanned, 0);

  if (allFindings.length === 0) {
    console.log(chalk.green.bold("  No security issues found!"));
    console.log(chalk.dim(`  Scanned ${totalFiles} files`));
    console.log();
    return;
  }

  for (const finding of allFindings) {
    printFinding(finding);
  }

  printSummary(allFindings, totalFiles);
}

function printFinding(f: Finding): void {
  console.log(`  ${SEVERITY_ICONS[f.severity]}  ${chalk.bold(f.title)}`);
  console.log(chalk.dim(`    ${f.file}:${f.line}`));
  console.log();

  if (f.code) {
    console.log(chalk.dim("    > ") + chalk.red(f.code));
    console.log();
  }

  // Wrap description at ~70 chars
  const descLines = wordWrap(f.description, 70);
  for (const line of descLines) {
    console.log(chalk.white(`    ${line}`));
  }
  console.log();

  console.log(chalk.green(`    Fix: ${f.fix}`));

  if (f.fixedCode) {
    const fixedLines = f.fixedCode.split("\n");
    for (const line of fixedLines) {
      console.log(chalk.green.dim(`    + ${line}`));
    }
  }

  if (f.command) {
    console.log(chalk.cyan(`    Run: ${f.command}`));
  }

  console.log();
  console.log(chalk.dim("  " + "─".repeat(60)));
  console.log();
}

function printSummary(findings: Finding[], totalFiles: number): void {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity]++;
  }

  console.log();

  const parts = [];
  if (counts.critical > 0) parts.push(chalk.bgRed.white.bold(` ${counts.critical} critical `));
  if (counts.high > 0) parts.push(chalk.red.bold(`${counts.high} high`));
  if (counts.medium > 0) parts.push(chalk.yellow(`${counts.medium} medium`));
  if (counts.low > 0) parts.push(chalk.blue(`${counts.low} low`));

  console.log(`  Found: ${parts.join(chalk.dim(" · "))}`);
  console.log(chalk.dim(`  Scanned ${totalFiles} files`));
  console.log();

  if (counts.critical > 0) {
    console.log(chalk.bgRed.white.bold("  Your project has critical security issues. "));
    console.log(chalk.red.bold("  Fix CRITICAL items immediately before deploying."));
  } else if (counts.high > 0) {
    console.log(chalk.red.bold("  Your project has serious security issues."));
    console.log(chalk.red("  Fix HIGH items before deploying to production."));
  } else if (counts.medium > 0) {
    console.log(chalk.yellow("  Your project has some security concerns."));
    console.log(chalk.yellow("  Consider fixing MEDIUM items to improve security."));
  } else {
    console.log(chalk.blue("  Minor issues found. Your project looks mostly secure."));
  }
  console.log();
}

function wordWrap(text: string, maxLen: number): string[] {
  const words = text.split(" ");
  const lines: string[] = [];
  let current = "";

  for (const word of words) {
    if (current.length + word.length + 1 > maxLen) {
      lines.push(current);
      current = word;
    } else {
      current = current ? current + " " + word : word;
    }
  }
  if (current) lines.push(current);
  return lines;
}
