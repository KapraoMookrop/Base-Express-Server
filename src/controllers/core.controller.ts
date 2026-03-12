import e, { type NextFunction, type Request, type Response } from "express";
import * as coreService from "../services/core.service.js";

export async function VerifyEmail(req: Request, res: Response, next: NextFunction) {
    try {
        const { verifyToken } = req.query;
        await coreService.VerifyEmail(verifyToken as string);
        res.json({ message: "Email verified successfully" });
    } catch (error) {
        next(error);
    }
}

export async function Enable2FA(req: Request, res: Response, next: NextFunction) {
    try {
        const { userId, email } = (req as any).user;
        const result = await coreService.Enable2FA(userId, email);
        res.json(result);
    } catch (error) {
        next(error);
    }
}

export async function Verify2FA(req: Request, res: Response, next: NextFunction) {
    try {
        const { token, type, email } = req.body;
        const result = await coreService.Verify2FA(email, token, type);
        res.json(result);
    } catch (error) {
        next(error);
    }
}
