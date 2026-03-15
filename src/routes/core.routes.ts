import { Router } from "express";
import * as coreController from "../controllers/core.controller.js";
import { authenticateToken } from "../middleware/auth.middleware.js";

const router = Router();

router.get("/VerifyEmail", coreController.VerifyEmail);
router.post("/Enable2FA", authenticateToken, coreController.Enable2FA);
router.post("/Disable2FA", authenticateToken, coreController.Enable2FA);
router.post("/Verify2FA", coreController.Verify2FA);
router.post("/SendForgotPasswordEmail", coreController.SendForgotPasswordEmail);
router.post("/ChangePassword", coreController.ChangePassword);

export default router;