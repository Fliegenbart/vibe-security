#!/usr/bin/env node

import { Command } from "commander";
import { resolve } from "path";
import { existsSync } from "fs";
import { writeFile } from "fs/promises";
import { runScan } from "./scanner.js";
import { printHeader, printFramework, printResults } from "./reporter/terminal.js";
import { generateJsonReport } from "./reporter/json.js";

const program = new Command();

program
  .name("vibesafe")
  .description("Security scanner for AI-generated (vibe-coded) projects")
  .version("1.0.0")
  .argument("[directory]", "Project directory to scan", ".")
  .option("--json [file]", "Output results as JSON (optionally to a file)")
  .option("--quiet", "Only show critical and high severity findings")
  .action(async (directory: string, options: { json?: string | boolean; quiet?: boolean }) => {
    const rootDir = resolve(directory);

    if (!existsSync(rootDir)) {
      console.error(`Error: Directory "${rootDir}" does not exist.`);
      process.exit(1);
    }

    printHeader();

    const { framework, results } = await runScan(rootDir);

    printFramework(framework.name, framework.type);

    if (options.quiet) {
      for (const r of results) {
        r.findings = r.findings.filter((f) => f.severity === "critical" || f.severity === "high");
      }
    }

    if (options.json) {
      const report = generateJsonReport(results, framework);
      if (typeof options.json === "string") {
        await writeFile(options.json, JSON.stringify(report, null, 2));
        console.log(`  JSON report written to ${options.json}`);
      } else {
        console.log(JSON.stringify(report, null, 2));
      }
    } else {
      printResults(results);
    }

    // Exit with error code if critical findings
    const hasCritical = results.some((r) => r.findings.some((f) => f.severity === "critical"));
    if (hasCritical) process.exit(1);
  });

program.parse();
