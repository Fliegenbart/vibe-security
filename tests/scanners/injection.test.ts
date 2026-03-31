import { describe, it, expect } from "vitest";
import { resolve } from "path";
import { injectionScanner } from "../../src/scanners/injection.js";
import { getProjectFiles } from "../../src/utils.js";
import { detectFramework } from "../../src/detectors/frameworks.js";

const VULNERABLE_DIR = resolve(__dirname, "../fixtures/vulnerable-app");
const SECURE_DIR = resolve(__dirname, "../fixtures/secure-app");

describe("Injection Scanner", () => {
  it("should find injection vulnerabilities", async () => {
    const files = await getProjectFiles(VULNERABLE_DIR);
    const framework = await detectFramework(VULNERABLE_DIR);
    const result = await injectionScanner.scan({ rootDir: VULNERABLE_DIR, files, framework });

    const titles = result.findings.map((f) => f.title);

    expect(titles).toContain("SQL Injection vulnerability");
    expect(titles).toContain("Command Injection vulnerability");
    expect(titles).toContain("Cross-Site Scripting (XSS) vulnerability");
    expect(titles).toContain("Server-Side Request Forgery (SSRF)");
  });

  it("should find no injection issues in secure app", async () => {
    const files = await getProjectFiles(SECURE_DIR);
    const framework = await detectFramework(SECURE_DIR);
    const result = await injectionScanner.scan({ rootDir: SECURE_DIR, files, framework });

    expect(result.findings).toHaveLength(0);
  });
});
