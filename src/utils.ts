import { readFile } from "fs/promises";
import fg from "fast-glob";

export async function getProjectFiles(
  rootDir: string,
  patterns: string[] = ["**/*.{ts,tsx,js,jsx,py,json,yaml,yml,env,sql}"],
  ignore: string[] = ["**/node_modules/**", "**/dist/**", "**/build/**", "**/.next/**", "**/venv/**", "**/__pycache__/**", "**/coverage/**"]
): Promise<string[]> {
  return fg(patterns, { cwd: rootDir, ignore, absolute: false });
}

export async function readFileLines(rootDir: string, filePath: string): Promise<string[]> {
  try {
    const content = await readFile(`${rootDir}/${filePath}`, "utf-8");
    return content.split("\n");
  } catch {
    return [];
  }
}

export async function readFileContent(rootDir: string, filePath: string): Promise<string> {
  try {
    return await readFile(`${rootDir}/${filePath}`, "utf-8");
  } catch {
    return "";
  }
}

export function matchesAny(line: string, patterns: RegExp[]): RegExp | null {
  for (const p of patterns) {
    if (p.test(line)) return p;
  }
  return null;
}

export function fileHasExtension(file: string, exts: string[]): boolean {
  return exts.some((ext) => file.endsWith(ext));
}

export function isSourceFile(file: string): boolean {
  return fileHasExtension(file, [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
}

export function isPythonFile(file: string): boolean {
  return fileHasExtension(file, [".py"]);
}
