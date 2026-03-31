import type { Scanner, ScanContext, ScanResult, Finding } from "../types.js";
import { readFileLines, isSourceFile, isPythonFile } from "../utils.js";

// SQL Injection patterns
const SQL_CONCAT = [
  // Template literals in SQL
  /(?:query|execute|raw|sql)\s*\(\s*`[^`]*\$\{/i,
  // String concatenation in SQL
  /(?:query|execute|raw|sql)\s*\(\s*["'][^"']*["']\s*\+/i,
  // f-strings in Python SQL
  /(?:execute|cursor\.execute|\.query)\s*\(\s*f["']/i,
  // % formatting in Python SQL
  /(?:execute|cursor\.execute)\s*\(\s*["'][^"']*%s[^"']*["']\s*%/i,
];

// XSS patterns
const XSS_PATTERNS = [
  /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
  /\.innerHTML\s*=\s*(?!["']\s*$)/,
  /document\.write\s*\(/,
  /\$\(\s*["'][^"']*["']\s*\)\.html\s*\(/,
  /v-html\s*=/,
];

// Command Injection patterns
const CMD_INJECTION = [
  /(?:exec|execSync|spawn|spawnSync)\s*\(\s*`[^`]*\$\{/,
  /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/,
  /child_process.*(?:exec|spawn)\s*\(\s*[^"'`\s]/,
  /subprocess\.(?:run|call|Popen)\s*\(\s*f["']/,
  /os\.system\s*\(\s*f?["'][^"']*\{/,
];

// SSRF patterns
const SSRF_PATTERNS = [
  /(?:fetch|axios\.get|axios\.post|got|request)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|url|userUrl|targetUrl)/,
  /(?:fetch|axios\.get|axios\.post|got|request)\s*\(\s*`[^`]*\$\{(?:req|request|params|query|body)\./,
  /requests\.(?:get|post)\s*\(\s*(?:request\.|url|target)/,
];

// Path Traversal patterns
const PATH_TRAVERSAL = [
  /(?:readFile|readFileSync|createReadStream|readdir|readdirSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/,
  /(?:readFile|readFileSync|createReadStream)\s*\(\s*`[^`]*\$\{(?:req|request|params|query|body)\./,
  /open\s*\(\s*(?:request\.|f["'][^"']*\{)/,
  /path\.join\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/,
];

interface PatternGroup {
  patterns: RegExp[];
  severity: "critical" | "high";
  title: string;
  description: string;
  fix: string;
  fixedCode?: string;
}

const GROUPS: PatternGroup[] = [
  {
    patterns: SQL_CONCAT,
    severity: "critical",
    title: "SQL Injection vulnerability",
    description:
      "Your code builds SQL queries by inserting variables directly into the query string. An attacker can manipulate the input to read, modify, or delete your entire database.",
    fix: "Use parameterized queries (prepared statements) instead of string concatenation.",
  },
  {
    patterns: XSS_PATTERNS,
    severity: "high",
    title: "Cross-Site Scripting (XSS) vulnerability",
    description:
      "Unescaped user content is inserted directly into the page HTML. An attacker can inject JavaScript that runs in every visitor's browser — stealing sessions, redirecting users, or defacing the page.",
    fix: "Never insert raw HTML from user input. Use text content or a sanitization library like DOMPurify.",
  },
  {
    patterns: CMD_INJECTION,
    severity: "critical",
    title: "Command Injection vulnerability",
    description:
      "User input is passed directly into a shell command. An attacker can append their own commands (e.g., `; rm -rf /`) and execute anything on your server.",
    fix: "Use execFile() with an argument array instead of exec() with string interpolation. Never pass user input to a shell.",
  },
  {
    patterns: SSRF_PATTERNS,
    severity: "high",
    title: "Server-Side Request Forgery (SSRF)",
    description:
      "User-supplied URLs are fetched by your server without validation. An attacker can make your server request internal services (databases, cloud metadata APIs) that should not be publicly accessible.",
    fix: "Validate and allowlist URLs before fetching. Block private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x).",
  },
  {
    patterns: PATH_TRAVERSAL,
    severity: "high",
    title: "Path Traversal vulnerability",
    description:
      "User input is used directly in file paths. An attacker can use `../` sequences to read any file on your server (e.g., `/etc/passwd`, `.env`, database files).",
    fix: "Use path.resolve() and verify the resolved path starts with your intended directory. Never trust user-supplied file paths.",
  },
];

export const injectionScanner: Scanner = {
  name: "Injection",
  async scan(ctx: ScanContext): Promise<ScanResult> {
    const findings: Finding[] = [];
    const sourceFiles = ctx.files.filter((f) => isSourceFile(f) || isPythonFile(f));

    for (const file of sourceFiles) {
      const lines = await readFileLines(ctx.rootDir, file);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;

        // Skip comments
        if (/^\s*(\/\/|#|\/\*|\*)/.test(line)) continue;

        for (const group of GROUPS) {
          let matched = false;
          for (const pattern of group.patterns) {
            if (pattern.test(line)) {
              findings.push({
                severity: group.severity,
                title: group.title,
                file,
                line: lineNum,
                description: group.description,
                fix: group.fix,
                code: line.trim(),
              });
              matched = true;
              break;
            }
          }
          if (matched) break;
        }
      }
    }

    return { scanner: "Injection", findings, filesScanned: sourceFiles.length };
  },
};
