import rateLimit from "express-rate-limit";

export const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 minutes
  max: 3,                   // Max 3 OTP requests per 5 minutes
  message: {
    success: false,
    message: "Too many OTP requests. Please try again after 5 minutes."
  },
  standardHeaders: true,
  legacyHeaders: false,
});
