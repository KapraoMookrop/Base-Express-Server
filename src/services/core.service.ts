import pool from "../config/database.js";
import { AppError } from "../errors/AppError.js";
import { UserStatus, Verify2FAType } from "../module/Enum.js";
import type { LoginResponseData } from "../module/LoginResponseData.js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import QRCode from "qrcode";
import bcrypt from "bcrypt";
import speakeasy from "speakeasy";
import { ENV } from "../config/env.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function SendVerifyEmail(email: string, token: string) {
    const sqlCoreMailPassword = await pool.query(
        "select * from b.configuration where code = 'CoreMailPassword'"
    );
    const CoreMailPassword = sqlCoreMailPassword.rows[0].value;

    const sqlCoreMailUser = await pool.query(
        "select * from b.configuration where code = 'CoreMailUser'"
    );
    const CoreMailUser = sqlCoreMailUser.rows[0].value;

    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 587,
        secure: false,
        auth: {
            user: CoreMailUser,
            pass: CoreMailPassword
        }
    });

    const verification_link = `${ENV.CLIENT_URL}/${token}`;
    const replacements: MailTemplateReplacements = {
        header: `<h1 class="logo">SafeTrade</h1>
                 <p style="margin: 10px 0 0; opacity: 0.8; font-weight: 300;">Safe & Secure Computer Marketplace</p>`,
        description: `<h2 class="welcome-text">ยืนยันที่อยู่อีเมลของคุณ</h2>
                      <p class="description">
                            ขอบคุณที่ร่วมเป็นส่วนหนึ่งกับ SafeTrade!<br>
                            อีกเพียงขั้นตอนเดียวเท่านั้น เพื่อเริ่มการซื้อขายที่ปลอดภัย<br>
                            โปรดคลิกที่ปุ่มด้านล่างเพื่อยืนยันอีเมลของคุณ
                      </p>`,
        body: `<div class="btn-container">
                    <a href="${verification_link}" class="btn">ยืนยันอีเมลของฉัน</a>
                </div>
                <p style="font-size: 14px; color: #9ca3af;">
                    หากปุ่มด้านบนใช้งานไม่ได้ โปรดคัดลอกลิงก์ด้านล่างไปวางในเบราว์เซอร์ของคุณ:<br>
                    <a href="${verification_link}"
                        style="color: #059669; word-break: break-all;">${verification_link}</a>
                </p>

                <div class="security-note">
                    <strong>ข้อควรระวัง:</strong> หากคุณไม่ได้เป็นผู้สร้างบัญชีนี้
                    โปรดเพิกเฉยต่ออีเมลฉบับนี้ หรือติดต่อฝ่ายสนับสนุนหากมีข้อสงสัย
                </div>`
    }
    var html = GetMailTemplate("vemail-notify", replacements);

    await transporter.sendMail({
        from: `"Support Safe Trade" <${CoreMailUser}>`,
        to: email,
        subject: "ยืนยันอีเมลของคุณ",
        html: html
    });
}

export async function VerifyEmail(token: string) {
    const result = await pool.query("SELECT id, verify_token_expire FROM b.users WHERE verify_token = $1", [token]);
    if (result.rows.length === 0) {
        throw new AppError("ลิงก์ยืนยันอีเมลไม่ถูกต้อง", 400);
    }

    const user = result.rows[0];
    const now = new Date();
    if (user.verify_token_expire < now) {
        await pool.query("DELETE FROM b.users WHERE id = $1", [user.id]);
        throw new AppError("ลิงก์ยืนยันอีเมลหมดอายุแล้ว กรุณาสมัครสมาชิกใหม่", 400);
    }

    await pool.query(`UPDATE b.users SET status = '${UserStatus.ACTIVE}', verify_token = null, verify_token_expire = null WHERE id = $1`, [user.id]);
}

export async function Verify2FA(email: string, token: string, type: Verify2FAType) {
    console.log("Verifying 2FA for user:", email, "with token:", token, "and type:", type);
    const sqlSelect = await pool.query(
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
        FROM b.users u LEFT JOIN b.user_info ui ON u.id = ui.user_id
        WHERE u.email = $1`,
        [email]
    );

    if (sqlSelect.rows.length === 0) {
        throw new AppError("ไม่พบผู้ใช้งาน", 404);
    }

    const user = sqlSelect.rows[0];

    const verified = speakeasy.totp.verify({
        secret: user.twofa_secret,
        encoding: "base32",
        token: token,
        window: 1
    });

    if (!verified) {
        throw new AppError("รหัส 2FA ไม่ถูกต้อง", 401);
    }

    if (type === Verify2FAType.VERIFYENABLE) {
        await pool.query(
            `UPDATE b.users SET twofa_enabled = true WHERE id = $1`,
            [user.id]
        );
    } else if (type === Verify2FAType.VERIFYLOGIN) {
        const loginResponseData = await SignJWT(user);
        return loginResponseData;
    } else {
        throw new AppError("ประเภทการยืนยัน 2FA ไม่ถูกต้อง", 400);
    }
}

export async function Enable2FA(userId: string, email: string) {

    console.log("Enabling 2FA for user:", userId, email);
    const secret = speakeasy.generateSecret({
        length: 20,
        name: "SafeTrade:" + email
    });

    console.log("Secret for 2FA:", secret.base32);

    const qr = await QRCode.toDataURL(secret.otpauth_url as string);

    await pool.query(
        `UPDATE b.users SET twofa_secret = $1 WHERE id = $2`,
        [secret.base32, userId]
    );

    return {
        qr,
        secret: secret.base32
    };
}

export async function Disable2FA(userId: string) {
    await pool.query(
        `UPDATE b.users SET twofa_enabled = false, twofa_secret = null WHERE id = $1`,
        [userId]
    );
}

export async function SignJWT(user: any) {
    const token = jwt.sign(
        {
            userId: user.id,
            email: user.email,
            role: user.role,
            userStatus: user.status,
            isEnabled2FA: user.twofa_enabled,
            name: user.name,
            surname: user.surname,
            phone_number: user.phone_number,
        },
        ENV.JWT_SECRET,
        { expiresIn: "1d" }
    );

    const loginResponseData: LoginResponseData = {
        Email: user.email,
        Role: user.role,
        UserStatus: user.status,
        JWT: token,
        IsEnabled2FA: user.twofa_enabled,
        Name: user.name,
        SurName: user.surname,
        Phone: user.phone_number,
    };

    return loginResponseData;
}

export async function SendForgotPasswordEmail(email: string) {
    const setTokenResult = await pool.query(
        "UPDATE ct.users SET verify_token = gen_random_uuid(), verify_token_expire = NOW() + INTERVAL '1 hour' WHERE email = $1 RETURNING verify_token",
        [email]
    );

    const sqlCoreMailPassword = await pool.query(
        "select * from ct.configuration where code = 'CoreMailPassword'"
    );
    const CoreMailPassword = sqlCoreMailPassword.rows[0].value;
    const sqlCoreMailUser = await pool.query(
        "select * from ct.configuration where code = 'CoreMailUser'"
    );
    const CoreMailUser = sqlCoreMailUser.rows[0].value;

    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 587,
        secure: false,
        auth: {
            user: CoreMailUser,
            pass: CoreMailPassword
        }
    });

    const verification_link = `${ENV.CLIENT_URL}/change-password/${setTokenResult.rows[0].verify_token}`;
    const replacements: MailTemplateReplacements = {
        header: `<h1 class="logo">SafeTrade</h1>
                <p style="margin: 10px 0 0; opacity: 0.8; font-weight: 300;">Safe & Secure Computer Marketplace</p>`,
        description: `<h2 class="welcome-text">เราได้รับคำขอเปลี่ยนรหัสผ่านจากคุณ</h2>
                      <p class="description">
                        หากคุณไม่ได้ทำการขอเปลี่ยนรหัสผ่านนี้</br>
                        กรุณาอย่าคลิกที่ปุ่มด้านล่างและแจ้งให้เราทราบทันทีเพื่อความปลอดภัยของบัญชีคุณ
                      </p>`,
        body: `<div class="btn-container">
                    <a href="${verification_link}" class="btn">เปลี่ยนรหัสผ่าน</a>
                </div>
                <p style="font-size: 14px; color: #9ca3af;">
                    หากปุ่มด้านบนใช้งานไม่ได้ โปรดคัดลอกลิงก์ด้านล่างไปวางในเบราว์เซอร์ของคุณ:<br>
                    <a href="${verification_link}"
                        style="color: #059669; word-break: break-all;">${verification_link}</a>
                </p>`
    }

    var html = GetMailTemplate("email-notify", replacements);
    await transporter.sendMail({
        from: `"Support Safe Trade" <${CoreMailUser}>`,
        to: email,
        subject: "คำขอเปลี่ยนรหัสผ่าน",
        html: html
    });
}

export async function ChangePassword(token: string, newPassword: string) {
    const result = await pool.query("SELECT id, verify_token_expire FROM ct.users WHERE verify_token = $1", [token]);
    if (result.rows.length === 0) {
        throw new AppError("ลิงก์เปลี่ยนรหัสผ่านไม่ถูกต้อง", 400);
    }

    const userId = result.rows[0].id;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE ct.users SET password_hash = $1, verify_token = NULL, verify_token_expire = NULL WHERE id = $2", [hashedPassword, userId]);
}

function GetMailTemplate(templateName: string, replacements: MailTemplateReplacements) {
    const templatePath = path.join(__dirname, "../templates", `${templateName}.html`);
    let html = fs.readFileSync(templatePath, "utf8");
    html = html.replaceAll("{{header}}", replacements.header);
    html = html.replaceAll("{{description}}", replacements.description);
    html = html.replaceAll("{{body}}", replacements.body);

    return html;
}

interface MailTemplateReplacements {
    header: string;
    description: string;
    body: string;
}