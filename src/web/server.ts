import express from "express";
import { execSync } from "child_process";
import { mkdtempSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { runScan } from "../scanner.js";
import { generateJsonReport } from "../reporter/json.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
app.use(express.json());

// Serve static files
app.use(express.static(join(__dirname, "../../web/public")));

// Health check
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Scan endpoint
app.post("/api/scan", async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== "string") {
    res.status(400).json({ error: "URL is required" });
    return;
  }

  // Validate GitHub URL
  const githubPattern = /^https?:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/;
  if (!githubPattern.test(url.trim())) {
    res.status(400).json({ error: "Please enter a valid GitHub repository URL (e.g. https://github.com/user/repo)" });
    return;
  }

  const cleanUrl = url.trim().replace(/\/$/, "");
  let tmpDir: string | null = null;

  try {
    // Create temp directory
    tmpDir = mkdtempSync(join(tmpdir(), "vibesafe-"));

    // Shallow clone (faster, less data)
    execSync(`git clone --depth 1 "${cleanUrl}.git" "${tmpDir}/repo"`, {
      timeout: 60_000,
      stdio: "pipe",
    });

    const repoDir = join(tmpDir, "repo");

    // Run scan
    const { framework, results } = await runScan(repoDir);
    const report = generateJsonReport(results, framework);

    res.json(report);
  } catch (err: any) {
    if (err.message?.includes("timeout")) {
      res.status(408).json({ error: "Repository clone timed out. Try a smaller repository." });
    } else if (err.message?.includes("not found") || err.status === 128) {
      res.status(404).json({ error: "Repository not found. Make sure it's a public GitHub repo." });
    } else {
      console.error("Scan error:", err.message);
      res.status(500).json({ error: "Scan failed. Make sure the repository is public and accessible." });
    }
  } finally {
    // Cleanup
    if (tmpDir && existsSync(tmpDir)) {
      try {
        rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
  }
});

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`\n  vibesafe web scanner running at http://localhost:${PORT}\n`);
});
