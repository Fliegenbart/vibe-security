import { describe, it, expect } from "vitest";
import { resolve } from "path";
import { configScanner } from "../../src/scanners/config.js";
import { getProjectFiles } from "../../src/utils.js";
import { detectFramework } from "../../src/detectors/frameworks.js";

const VULNERABLE_DIR = resolve(__dirname, "../fixtures/vulnerable-app");
const SECURE_DIR = resolve(__dirname, "../fixtures/secure-app");

describe("Config Scanner", () => {
  it("should find config vulnerabilities", async () => {
    const files = await getProjectFiles(VULNERABLE_DIR);
    const framework = await detectFramework(VULNERABLE_DIR);
    const result = await configScanner.scan({ rootDir: VULNERABLE_DIR, files, framework });

    const titles = result.findings.map((f) => f.title);

    expect(titles).toContain(".env file not in .gitignore");
    expect(titles).toContain("Permissive CORS configuration");
    expect(titles).toContain("No security headers middleware");
    expect(result.findings.some((f) => f.title.includes("Default database credential"))).toBe(true);
    expect(result.findings.some((f) => f.title.includes("port exposed"))).toBe(true);
  });

  it("should find no config issues in secure app", async () => {
    const files = await getProjectFiles(SECURE_DIR);
    const framework = await detectFramework(SECURE_DIR);
    const result = await configScanner.scan({ rootDir: SECURE_DIR, files, framework });

    expect(result.findings).toHaveLength(0);
  });
});
