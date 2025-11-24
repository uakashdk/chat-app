import express from "express";
import { sendEmailOtpSchema, sendOtpSchema } from "../Validation/authValidation.js";
import validate from "../middleware/validate.js";
import { login, loginEmail, verifyEmailOtp, verifyMobileOtp } from "../controller/authController.js";
import { otpLimiter } from "../middleware/rateLimitter.js";


const router = express.Router();


router.post("/login-mobile",validate(sendOtpSchema),otpLimiter,login)

router.post("/verify-otp",verifyMobileOtp);

router.post("/login-email",validate(sendEmailOtpSchema),otpLimiter,loginEmail)

router.post("/verfy-emailOtp",verifyEmailOtp);


export default router;