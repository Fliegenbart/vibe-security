import { describe, it, expect } from "vitest";
import { resolve } from "path";
import { authScanner } from "../../src/scanners/auth.js";
import { getProjectFiles } from "../../src/utils.js";
import { detectFramework } from "../../src/detectors/frameworks.js";

const VULNERABLE_DIR = resolve(__dirname, "../fixtures/vulnerable-app");
const SECURE_DIR = resolve(__dirname, "../fixtures/secure-app");

describe("Auth Scanner", () => {
  it("should find vulnerabilities in vulnerable app", async () => {
    const files = await getProjectFiles(VULNERABLE_DIR);
    const framework = await detectFramework(VULNERABLE_DIR);
    const result = await authScanner.scan({ rootDir: VULNERABLE_DIR, files, framework });

    const titles = result.findings.map((f) => f.title);

    expect(titles).toContain("Hardcoded JWT secret");
    expect(titles).toContain("Hardcoded credential");
    expect(titles).toContain("Auth token stored in localStorage/sessionStorage");
    expect(result.findings.some((f) => f.title.includes("Weak bcrypt"))).toBe(true);
  });

  it("should find no auth issues in secure app", async () => {
    const files = await getProjectFiles(SECURE_DIR);
    const framework = await detectFramework(SECURE_DIR);
    const result = await authScanner.scan({ rootDir: SECURE_DIR, files, framework });

    expect(result.findings).toHaveLength(0);
  });
});
