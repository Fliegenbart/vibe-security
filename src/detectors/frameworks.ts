import { readFileContent } from "../utils.js";
import type { FrameworkInfo } from "../types.js";

export async function detectFramework(rootDir: string): Promise<FrameworkInfo> {
  const pkg = await readFileContent(rootDir, "package.json");
  const reqTxt = await readFileContent(rootDir, "requirements.txt");
  const pyproject = await readFileContent(rootDir, "pyproject.toml");

  if (pkg) {
    try {
      const parsed = JSON.parse(pkg);
      const allDeps = {
        ...parsed.dependencies,
        ...parsed.devDependencies,
      };
      const depNames = Object.keys(allDeps || {});

      if (depNames.includes("next")) {
        return { name: "Next.js", type: "fullstack", language: "typescript" };
      }
      if (depNames.includes("nuxt")) {
        return { name: "Nuxt", type: "fullstack", language: "typescript" };
      }
      if (depNames.includes("express")) {
        return { name: "Express", type: "backend", language: hasTS(depNames) ? "typescript" : "javascript" };
      }
      if (depNames.includes("fastify")) {
        return { name: "Fastify", type: "backend", language: hasTS(depNames) ? "typescript" : "javascript" };
      }
      if (depNames.includes("hono")) {
        return { name: "Hono", type: "backend", language: "typescript" };
      }
      if (depNames.includes("react")) {
        return { name: "React", type: "frontend", language: hasTS(depNames) ? "typescript" : "javascript" };
      }
      if (depNames.includes("vue")) {
        return { name: "Vue", type: "frontend", language: hasTS(depNames) ? "typescript" : "javascript" };
      }
      if (depNames.includes("svelte") || depNames.includes("@sveltejs/kit")) {
        return { name: "SvelteKit", type: "fullstack", language: "typescript" };
      }

      return {
        name: "Node.js",
        type: "unknown",
        language: hasTS(depNames) ? "typescript" : "javascript",
      };
    } catch {
      // invalid package.json
    }
  }

  if (reqTxt || pyproject) {
    const content = reqTxt || pyproject;
    if (content.includes("django") || content.includes("Django")) {
      return { name: "Django", type: "fullstack", language: "python" };
    }
    if (content.includes("fastapi") || content.includes("FastAPI")) {
      return { name: "FastAPI", type: "backend", language: "python" };
    }
    if (content.includes("flask") || content.includes("Flask")) {
      return { name: "Flask", type: "backend", language: "python" };
    }
    return { name: "Python", type: "unknown", language: "python" };
  }

  return { name: "Unknown", type: "unknown", language: "unknown" };
}

function hasTS(deps: string[]): boolean {
  return deps.includes("typescript") || deps.includes("@types/node");
}
