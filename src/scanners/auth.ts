import type { Scanner, ScanContext, ScanResult, Finding } from "../types.js";
import { readFileLines, isSourceFile, isPythonFile } from "../utils.js";

const WEAK_JWT_SECRETS = [
  /jwt\.sign\s*\([^)]*,\s*["'](secret|password|key|test|abc|123|admin|jwt_secret|changeme|your[_-]?secret)['"]/i,
  /sign\(\s*\{[^}]*\}\s*,\s*["'](secret|password|key|test|abc|123|admin|jwt_secret|changeme|your[_-]?secret)['"]/i,
  /SECRET_KEY\s*=\s*["'](secret|password|key|test|abc|123|admin|changeme|your[_-]?secret)['"]/i,
];

const HARDCODED_CREDENTIALS = [
  /(?:password|passwd|pwd|api_key|apikey|api_secret|secret_key|access_token|auth_token|private_key)\s*[:=]\s*["'][^"']{3,}["']/i,
];

const INSECURE_SESSION = [
  /localStorage\.setItem\s*\(\s*["'](?:token|jwt|session|auth|access_token|refresh_token)["']/i,
  /sessionStorage\.setItem\s*\(\s*["'](?:token|jwt|session|auth|access_token)["']/i,
];

const WEAK_BCRYPT = [
  /bcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*([1-9])\s*\)/,
  /genSalt(?:Sync)?\s*\(\s*([1-9])\s*\)/,
];

const NO_AUTH_CHECK = [
  /if\s*\(\s*(?:user|req\.user|session)\.(?:isAdmin|is_admin|role)\s*(?:===?\s*["']admin["']|===?\s*true)\s*\)/,
];

const CSRF_MISSING_PATTERNS = [
  /app\.(?:post|put|patch|delete)\s*\(/,
];

export const authScanner: Scanner = {
  name: "Auth",
  async scan(ctx: ScanContext): Promise<ScanResult> {
    const findings: Finding[] = [];
    const sourceFiles = ctx.files.filter((f) => isSourceFile(f) || isPythonFile(f));

    for (const file of sourceFiles) {
      const lines = await readFileLines(ctx.rootDir, file);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;

        // Weak JWT secrets
        for (const pattern of WEAK_JWT_SECRETS) {
          if (pattern.test(line)) {
            findings.push({
              severity: "critical",
              title: "Hardcoded JWT secret",
              file,
              line: lineNum,
              description:
                "Your JWT is signed with a weak, hardcoded secret. Anyone who guesses it can forge authentication tokens and impersonate any user.",
              fix: "Use a strong random secret from an environment variable.",
              code: line.trim(),
              command: 'openssl rand -base64 32',
            });
            break;
          }
        }

        // Hardcoded credentials
        for (const pattern of HARDCODED_CREDENTIALS) {
          if (pattern.test(line)) {
            // Skip if it's just reading from env
            if (/process\.env|os\.environ|import\.meta\.env/.test(line)) continue;
            // Skip comments
            if (/^\s*(\/\/|#|\/\*)/.test(line)) continue;
            // Skip if it's a type annotation or interface
            if (/:\s*string|interface\s|type\s/.test(line)) continue;

            findings.push({
              severity: "critical",
              title: "Hardcoded credential",
              file,
              line: lineNum,
              description:
                "A password, API key, or secret is hardcoded in your source code. If this code is on GitHub, these credentials are public.",
              fix: "Move the secret to a .env file and read it with process.env.",
              code: line.trim(),
            });
            break;
          }
        }

        // Insecure token storage
        for (const pattern of INSECURE_SESSION) {
          if (pattern.test(line)) {
            findings.push({
              severity: "high",
              title: "Auth token stored in localStorage/sessionStorage",
              file,
              line: lineNum,
              description:
                "Storing authentication tokens in localStorage makes them accessible to any JavaScript on the page. An XSS attack could steal all user sessions.",
              fix: "Use httpOnly cookies instead. They can't be accessed by JavaScript.",
              code: line.trim(),
            });
            break;
          }
        }

        // Weak bcrypt rounds
        for (const pattern of WEAK_BCRYPT) {
          const match = line.match(pattern);
          if (match && parseInt(match[1]) < 10) {
            findings.push({
              severity: "high",
              title: `Weak bcrypt salt rounds (${match[1]})`,
              file,
              line: lineNum,
              description:
                `bcrypt is using only ${match[1]} salt rounds. Modern GPUs can crack these quickly. Use at least 12 rounds.`,
              fix: "Increase salt rounds to at least 12.",
              code: line.trim(),
              fixedCode: line.trim().replace(/\d+/, "12"),
            });
            break;
          }
        }

        // Placeholder auth checks (AI pattern)
        for (const pattern of NO_AUTH_CHECK) {
          if (pattern.test(line)) {
            // Check if there's actual middleware or just a simple boolean check
            const surroundingCode = lines.slice(Math.max(0, i - 3), i + 5).join("\n");
            if (!/middleware|authenticate|verify|validate|decoded|payload/.test(surroundingCode)) {
              findings.push({
                severity: "medium",
                title: "Placeholder auth check (possible AI-generated pattern)",
                file,
                line: lineNum,
                description:
                  "This looks like a simple role check without proper authentication middleware. AI tools often generate these placeholder checks that look correct but don't actually verify the user's identity.",
                fix: "Add proper authentication middleware that verifies the JWT/session before checking roles.",
                code: line.trim(),
              });
            }
            break;
          }
        }
      }
    }

    return { scanner: "Auth", findings, filesScanned: sourceFiles.length };
  },
};
