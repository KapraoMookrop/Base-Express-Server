import pool from "../config/database.js";
import { type User } from "../module/user.model.js";

export async function getUsers(): Promise<User[]> {
  const result = await pool.query("SELECT * FROM users");
  return result.rows;
}