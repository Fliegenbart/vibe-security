import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

// Weak JWT secret - should be caught
const token = jwt.sign({ userId: 1 }, "secret", { expiresIn: "1h" });

// Weak bcrypt rounds - should be caught
const hash = bcrypt.hashSync("password123", 4);

// Hardcoded API key - should be caught
const API_KEY = "sk-proj-abc123def456";

export function login(username: string, password: string) {
  // Placeholder auth - should be caught
  if (user.isAdmin === true) {
    return { role: "admin" };
  }
}
