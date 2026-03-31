import { pool } from "../db";
import { exec } from "child_process";

export async function getUser(req: any, res: any) {
  const userId = req.params.id;

  // SQL Injection - should be caught
  const result = await pool.query(`SELECT * FROM users WHERE id = '${userId}'`);

  res.json(result.rows);
}

export async function runReport(req: any, res: any) {
  const filename = req.body.filename;

  // Command Injection - should be caught
  exec(`cat /reports/${filename}`, (err, stdout) => {
    res.send(stdout);
  });
}

export async function fetchUrl(req: any, res: any) {
  const url = req.query.url;

  // SSRF - should be caught
  const response = await fetch(req.query.url);
  res.json(await response.json());
}

export async function readDoc(req: any, res: any) {
  const path = req.query.path;

  // Path Traversal - should be caught
  const content = await readFile(req.query.path, "utf-8");
  res.send(content);
}
