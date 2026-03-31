import type { Scanner, ScanContext, ScanResult, Finding } from "../types.js";
import { readFileContent, readFileLines, getProjectFiles } from "../utils.js";
import fg from "fast-glob";

export const configScanner: Scanner = {
  name: "Config",
  async scan(ctx: ScanContext): Promise<ScanResult> {
    const findings: Finding[] = [];

    // 1. Check if .env files exist and are in .gitignore
    await checkEnvFiles(ctx, findings);

    // 2. Check for debug mode in production configs
    await checkDebugMode(ctx, findings);

    // 3. Check for permissive CORS
    await checkCors(ctx, findings);

    // 4. Check for default credentials in config/docker
    await checkDefaultCredentials(ctx, findings);

    // 5. Check for missing security headers
    await checkSecurityHeaders(ctx, findings);

    // 6. Check for exposed ports in docker-compose
    await checkDockerPorts(ctx, findings);

    return { scanner: "Config", findings, filesScanned: ctx.files.length };
  },
};

async function checkEnvFiles(ctx: ScanContext, findings: Finding[]) {
  const envFiles = await fg(["**/.env", "**/.env.local", "**/.env.production"], {
    cwd: ctx.rootDir,
    ignore: ["**/node_modules/**"],
    dot: true,
    absolute: false,
  });

  if (envFiles.length === 0) return;

  const gitignore = await readFileContent(ctx.rootDir, ".gitignore");

  for (const envFile of envFiles) {
    const basename = envFile.split("/").pop() || envFile;
    const isIgnored = gitignore.includes(basename) || gitignore.includes(".env");

    if (!isIgnored) {
      findings.push({
        severity: "critical",
        title: ".env file not in .gitignore",
        file: envFile,
        line: 1,
        description:
          `${envFile} contains sensitive data (API keys, database passwords) but is not listed in .gitignore. If you push to GitHub, these secrets become public.`,
        fix: `Add ${basename} to .gitignore immediately.`,
        command: `echo "${basename}" >> .gitignore`,
      });
    }

    // Check for actual secrets in .env
    const lines = await readFileLines(ctx.rootDir, envFile);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*#/.test(line) || !line.includes("=")) continue;

      // Check for placeholder/example values that look real
      if (/(?:sk-|pk_|rk_|ghp_|gho_|xoxb-|xoxp-)/.test(line)) {
        findings.push({
          severity: "high",
          title: "Real API key in .env file",
          file: envFile,
          line: i + 1,
          description:
            "This looks like a real API key (not a placeholder). Make sure this file is not committed to version control.",
          fix: "Verify this key is rotated if it was ever committed to git.",
          command: "git log --oneline -- " + envFile,
        });
        break; // One warning per file is enough
      }
    }
  }
}

async function checkDebugMode(ctx: ScanContext, findings: Finding[]) {
  const configFiles = ctx.files.filter((f) =>
    /\.(json|yaml|yml|toml|env|conf)$/i.test(f) || /config/i.test(f)
  );

  for (const file of configFiles) {
    const lines = await readFileLines(ctx.rootDir, file);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/DEBUG\s*[:=]\s*(?:true|1|yes|on)/i.test(line) && !/development|dev|local|test/i.test(file)) {
        findings.push({
          severity: "medium",
          title: "Debug mode enabled",
          file,
          line: i + 1,
          description:
            "Debug mode exposes detailed error messages, stack traces, and internal information that helps attackers understand your application's structure.",
          fix: "Set DEBUG=false in production configuration.",
          code: line.trim(),
        });
        break;
      }
    }
  }
}

async function checkCors(ctx: ScanContext, findings: Finding[]) {
  const sourceFiles = ctx.files.filter((f) => /\.(ts|tsx|js|jsx|py)$/.test(f));

  for (const file of sourceFiles) {
    const lines = await readFileLines(ctx.rootDir, file);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/(?:Access-Control-Allow-Origin|cors.*origin)\s*[:=]\s*["']\*["']/i.test(line) ||
          /cors\(\s*\)/.test(line)) {
        findings.push({
          severity: "medium",
          title: "Permissive CORS configuration",
          file,
          line: i + 1,
          description:
            "CORS is set to allow any website to make requests to your API. Malicious sites can make authenticated requests on behalf of your users.",
          fix: "Restrict CORS to your specific frontend domain(s).",
          code: line.trim(),
          fixedCode: 'cors({ origin: "https://your-frontend-domain.com" })',
        });
        break;
      }
    }
  }
}

async function checkDefaultCredentials(ctx: ScanContext, findings: Finding[]) {
  const configFiles = ctx.files.filter((f) =>
    /docker-compose|\.env|config\.(json|yaml|yml|ts|js)$/i.test(f)
  );

  const defaults = [
    /(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|DB_PASSWORD|DATABASE_PASSWORD)\s*[:=]\s*["']?(?:password|admin|root|123456|postgres|mysql|changeme|default)["']?/i,
    /(?:REDIS_PASSWORD)\s*[:=]\s*["']?(?:password|redis|changeme|default)["']?/i,
  ];

  for (const file of configFiles) {
    const lines = await readFileLines(ctx.rootDir, file);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of defaults) {
        if (pattern.test(line)) {
          findings.push({
            severity: "high",
            title: "Default database credential",
            file,
            line: i + 1,
            description:
              "A database is configured with a default/weak password. Automated scanners try these passwords first. If your database is network-accessible, it will be compromised.",
            fix: "Use a strong, randomly generated password.",
            command: 'openssl rand -base64 24',
            code: line.trim(),
          });
          break;
        }
      }
    }
  }
}

async function checkSecurityHeaders(ctx: ScanContext, findings: Finding[]) {
  // Only check if it's a web server project
  if (ctx.framework.type === "unknown" && ctx.framework.language === "unknown") return;

  const serverFiles = ctx.files.filter((f) =>
    /server\.(ts|js)|app\.(ts|js)|index\.(ts|js)|main\.(ts|js)$/i.test(f)
  );

  if (serverFiles.length === 0) return;

  // Check if helmet or security headers middleware is used
  let hasHelmet = false;
  for (const file of serverFiles) {
    const content = await readFileContent(ctx.rootDir, file);
    if (/helmet|security-headers|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security/i.test(content)) {
      hasHelmet = true;
      break;
    }
  }

  if (!hasHelmet && ctx.framework.type !== "frontend") {
    findings.push({
      severity: "medium",
      title: "No security headers middleware",
      file: serverFiles[0],
      line: 1,
      description:
        "Your server doesn't set security headers (CSP, HSTS, X-Frame-Options). Without these, your app is more vulnerable to clickjacking, XSS, and man-in-the-middle attacks.",
      fix: "Add the 'helmet' middleware to your Express/Fastify app.",
      command: "npm install helmet",
      fixedCode: 'import helmet from "helmet";\napp.use(helmet());',
    });
  }
}

async function checkDockerPorts(ctx: ScanContext, findings: Finding[]) {
  const dockerFiles = ctx.files.filter((f) => /docker-compose/i.test(f));

  const dangerousPorts = ["5432", "3306", "27017", "6379", "9200", "5672"];
  const portNames: Record<string, string> = {
    "5432": "PostgreSQL",
    "3306": "MySQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "5672": "RabbitMQ",
  };

  for (const file of dockerFiles) {
    const lines = await readFileLines(ctx.rootDir, file);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const port of dangerousPorts) {
        // Matches "5432:5432" or "0.0.0.0:5432:5432" (publicly exposed)
        if (new RegExp(`["']?(?:0\\.0\\.0\\.0:)?${port}:${port}["']?`).test(line)) {
          findings.push({
            severity: "high",
            title: `${portNames[port]} port exposed publicly`,
            file,
            line: i + 1,
            description:
              `${portNames[port]} (port ${port}) is exposed to the internet. Anyone can try to connect to your database directly.`,
            fix: `Bind to 127.0.0.1 only, or remove the port mapping and use Docker networking.`,
            code: line.trim(),
            fixedCode: `"127.0.0.1:${port}:${port}"`,
          });
          break;
        }
      }
    }
  }
}
