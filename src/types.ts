export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  severity: Severity;
  title: string;
  file: string;
  line: number;
  description: string;
  fix: string;
  code?: string;
  fixedCode?: string;
  command?: string;
}

export interface ScanResult {
  scanner: string;
  findings: Finding[];
  filesScanned: number;
}

export interface ScanContext {
  rootDir: string;
  files: string[];
  framework: FrameworkInfo;
}

export interface FrameworkInfo {
  name: string;
  type: "frontend" | "backend" | "fullstack" | "unknown";
  language: "typescript" | "javascript" | "python" | "unknown";
}

export interface Scanner {
  name: string;
  scan(ctx: ScanContext): Promise<ScanResult>;
}
