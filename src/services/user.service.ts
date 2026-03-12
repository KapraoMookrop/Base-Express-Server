import pool from "../config/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { type SignUpDataRequest } from "../module/SignUpDataRequest.js";
import { UserStatus, UserRole } from "../module/Enum.js";
import type { UUID } from "node:crypto";
import { type LoginResponseData } from "../module/LoginResponseData.js";
import { AppError } from "../errors/AppError.js";
import * as Core from "./core.service.js";

export async function SignUp(request: SignUpDataRequest): Promise<UUID> {
  const { Name, SurName, Email, Password, Phone } = request;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const existingEmail = await client.query(
      "SELECT id FROM b.users WHERE email = $1",
      [Email]
    );

    if (existingEmail.rows.length > 0) {
      throw new AppError("อีเมลนี้ถูกลงทะเบียนกับระบบแล้ว", 409);
    }

    const hashedPassword = await bcrypt.hash(Password, 10);

    const insertUserResult = await client.query(
      `INSERT INTO b.users 
        (email, password_hash, role, status) 
      VALUES ($1, $2, $3, $4) 
      RETURNING id, verify_token`,
      [Email, hashedPassword, UserRole.ADMIN, UserStatus.PENDING_VERIFICATION]
    );

    await client.query(
      `INSERT INTO b.user_info 
        (user_id, name, surname, phone_number) 
      VALUES ($1, $2, $3, $4)`,
      [
        insertUserResult.rows[0].id,
        Name,
        SurName,
        Phone
      ]
    );

    await Core.SendVerifyEmail(Email, insertUserResult.rows[0].verify_token);

    await client.query("COMMIT");

    return insertUserResult.rows[0].id;

  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function Login(email: string, password: string): Promise<LoginResponseData> {
  const result = await pool.query(
    `SELECT 
      u.id, 
      u.email, 
      u.password_hash, 
      u.role, 
      u.status, 
      u.twofa_enabled, 
      u.twofa_secret,
      ui.name,
      ui.surname,
      ui.phone_number
    FROM b.users u 
      LEFT JOIN b.user_info ui ON u.id = ui.user_id
    WHERE u.email = $1`,
    [email]
  );

  if (result.rows.length === 0) {
    throw new AppError("อีเมลนี้ยังไม่ได้ลงทะเบียนกับระบบ", 404);
  }

  const user = result.rows[0];

  if (user.status === UserStatus.PENDING_VERIFICATION) {
    throw new AppError("บัญชีของคุณกำลังรอการยืนยันตัวตน กรุณาเช็คอีเมลที่ได้ลงทะเบียนไว้กับระบบ", 403);
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);
  if (!isPasswordValid) {
    throw new AppError("รหัสผ่านไม่ถูกต้อง", 401);
  }

  if (user.twofa_enabled) {
    return {
      IsEnabled2FA: true,
    } as LoginResponseData;
  }

  const loginResponseData = await Core.SignJWT(user);

  return loginResponseData;
}