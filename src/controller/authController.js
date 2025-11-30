// controllers/authController.js
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";

import client from "../config/twillo.js";
import redisClient from "../config/redis.js";
import transport from "../config/nodemailer.js";
import User from "../modal/User.js";

const generateOtp = () => {
  const n = crypto.randomInt(100000, 1000000);
  return n.toString();
};

const getDeviceFingerprint = (req) => {
  const ua = req.headers["user-agent"] || "unknown";
  const ip = req.ip || req.headers["x-forwarded-for"] || "0.0.0.0";
  const str = `${ua}::${ip}`;
  return crypto.createHash("sha256").update(str).digest("hex");
};

const safeUser = (user) => {
  if (!user) return null;
  const u = user.toObject ? user.toObject() : { ...user };
  // remove sensitive fields
  delete u.password;
  delete u.__v;
  delete u.resetToken;
  delete u.sensitive;
  return u;
};

const generateTokens = (userId, phoneOrEmail) => {
  const jti = uuidv4(); // unique token id for rotation/tracking

  const accessToken = jwt.sign(
    {
      sub: userId,
      jti,
      aud: "securechat-client",
      /* include any claims you want */
      phoneOrEmail,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES || "15m" }
  );

  const refreshToken = jwt.sign(
    {
      sub: userId,
      jti,
      aud: "securechat-refresh",
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES || "7d" }
  );

  return { accessToken, refreshToken, jti };
};

const storeRefreshToken = async (userId, jti, refreshToken, ttlSeconds) => {
  const key = `refresh:${userId}:${jti}`;
  await redisClient.set(key, refreshToken, "EX", ttlSeconds);
  await redisClient.set(`refresh_latest:${userId}`, jti, "EX", ttlSeconds);
  return key;
};

// invalidate all refresh tokens for a user (used on forced logout)
const invalidateAllRefreshTokensForUser = async (userId) => {
  // If you track keys/prefixes, you can delete by scanning. For simplicity, delete the latest pointer.
  const latestJti = await redisClient.get(`refresh_latest:${userId}`);
  if (latestJti) {
    await redisClient.del(`refresh:${userId}:${latestJti}`);
    await redisClient.del(`refresh_latest:${userId}`);
  }
};

// OTP attempt counter and blocking
const incrementOtpAttempt = async (phoneOrEmail) => {
  const key = `otp_attempts:${phoneOrEmail}`;
  const attempts = await redisClient.incr(key);
  if (attempts === 1) {
    // set expiry - block window, e.g., 10 minutes
    await redisClient.expire(key, 10 * 60);
  }
  return attempts;
};

const resetOtpAttempts = async (phoneOrEmail) => {
  const key = `otp_attempts:${phoneOrEmail}`;
  await redisClient.del(key);
};

const getOtpAttempts = async (phoneOrEmail) => {
  const key = `otp_attempts:${phoneOrEmail}`;
  const val = await redisClient.get(key);
  return val ? parseInt(val, 10) : 0;
};

/**
 * Controllers
 */

// SEND OTP TO MOBILE
export const login = async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) {
      return res.status(400).json({ success: false, message: "Phone number is required" });
    }

    // throttle/resend protections are assumed on route-level limiter.
    // still add a short server-side resend cooldown key:
    const resendKey = `otp_resend_cooldown:${phone}`;
    const cooldown = await redisClient.get(resendKey);
    if (cooldown) {
      return res.status(429).json({ success: false, message: "Please wait before requesting another OTP" });
    }

    const otp = generateOtp();

    // store OTP in redis: otp:<phone> and set resend cooldown
    await redisClient.set(`otp:${phone}`, otp, "EX", 5 * 60); // 5 minutes
    await redisClient.set(resendKey, "1", "EX", 30); // 30s resend cooldown

    // send SMS via Twilio (do not log OTP)
    await client.messages.create({
      body: `Your SecureChat verification code is ${otp}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: `+91${phone}`, // adjust if phone already includes country
    });

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
    });
  } catch (error) {
    console.error("Twilio Error:", error?.message || error);
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP. Please try again later.",
    });
  }
};

// VERIFY MOBILE OTP
export const verifyMobileOtp = async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) {
      return res.status(400).json({ success: false, message: "Phone and OTP are required" });
    }

    // check blocking attempts
    const attempts = await getOtpAttempts(phone);
    if (attempts >= 5) {
      return res.status(429).json({ success: false, message: "Too many failed attempts. Try after some time." });
    }

    const storedOtp = await redisClient.get(`otp:${phone}`);
    if (!storedOtp) {
      return res.status(400).json({
        success: false,
        message: "OTP expired or not found. Please request a new one.",
      });
    }

    if (storedOtp !== otp) {
      // increment attempts
      const nowAttempts = await incrementOtpAttempt(phone);
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
        attempts: nowAttempts,
      });
    }

    // correct OTP: clear stored otp and reset attempts
    await redisClient.del(`otp:${phone}`);
    await resetOtpAttempts(phone);

    // find or create user
    let user = await User.findOne({ phone });
    if (!user) {
      user = await User.create({ phone });
    }

    // generate tokens
    const { accessToken, refreshToken, jti } = generateTokens(user._id.toString(), phone);

    // device fingerprint binding
    const deviceFingerprint = getDeviceFingerprint(req);
    const refreshTtlSeconds = parseInt(process.env.REFRESH_TOKEN_TTL_SECONDS || 7 * 24 * 60 * 60, 10);

    // store refresh token keyed by userId and jti
    await storeRefreshToken(user._id.toString(), jti, refreshToken, refreshTtlSeconds);

    // Optionally store device info for this jti (helps for multi-device listing)
    const deviceKey = `device:${user._id}:${jti}`;
    await redisClient.set(deviceKey, JSON.stringify({
      fingerprint: deviceFingerprint,
      userAgent: req.headers["user-agent"] || null,
      ip: req.ip || req.headers["x-forwarded-for"] || null,
      createdAt: Date.now(),
    }), "EX", refreshTtlSeconds);

    // set refresh token cookie (HttpOnly Secure)
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: refreshTtlSeconds * 1000,
      path: "/",
      domain: process.env.COOKIE_DOMAIN || undefined,
    });

    return res.status(200).json({
      success: true,
      message: "OTP verified successfully",
      accessToken,
      user: safeUser(user),
    });
  } catch (error) {
    console.error("verifyMobileOtp error:", error?.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// SEND OTP TO EMAIL
export const loginEmail = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const resendKey = `otp_resend_cooldown:email:${email}`;
    const cooldown = await redisClient.get(resendKey);
    if (cooldown) {
      return res.status(429).json({ success: false, message: "Please wait before requesting another OTP" });
    }

    const otp = generateOtp();

    // save OTP in Redis
    await redisClient.set(`emailOtp:${email}`, otp, "EX", 5 * 60);
    await redisClient.set(resendKey, "1", "EX", 30);

    // send OTP email
    await transport.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your SecureChat OTP Code",
      html: `
        <h2>Your SecureChat OTP is: <b>${otp}</b></h2>
        <p>This code will expire in 5 minutes.</p>
      `,
    });

    return res.status(200).json({
      success: true,
      message: "OTP sent to email successfully",
    });
  } catch (error) {
    console.error("Email OTP Error:", error?.message || error);
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP email. Please try again later.",
    });
  }
};

// VERIFY EMAIL OTP
export const verifyEmailOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Email and OTP are required" });
    }

    const attempts = await getOtpAttempts(`email:${email}`);
    if (attempts >= 5) {
      return res.status(429).json({ success: false, message: "Too many failed attempts. Try after some time." });
    }

    const storedOtp = await redisClient.get(`emailOtp:${email}`);
    if (!storedOtp) {
      return res.status(400).json({ success: false, message: "OTP expired or not found. Please request a new one." });
    }

    if (storedOtp !== otp) {
      const nowAttempts = await incrementOtpAttempt(`email:${email}`);
      return res.status(400).json({ success: false, message: "Invalid OTP", attempts: nowAttempts });
    }

    // correct OTP
    await redisClient.del(`emailOtp:${email}`);
    await resetOtpAttempts(`email:${email}`);

    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email });
    }

    const { accessToken, refreshToken, jti } = generateTokens(user._id.toString(), email);
    const deviceFingerprint = getDeviceFingerprint(req);
    const refreshTtlSeconds = parseInt(process.env.REFRESH_TOKEN_TTL_SECONDS || 7 * 24 * 60 * 60, 10);
    await storeRefreshToken(user._id.toString(), jti, refreshToken, refreshTtlSeconds);

    const deviceKey = `device:${user._id}:${jti}`;
    await redisClient.set(deviceKey, JSON.stringify({
      fingerprint: deviceFingerprint,
      userAgent: req.headers["user-agent"] || null,
      ip: req.ip || req.headers["x-forwarded-for"] || null,
      createdAt: Date.now(),
    }), "EX", refreshTtlSeconds);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: refreshTtlSeconds * 1000,
      path: "/",
      domain: process.env.COOKIE_DOMAIN || undefined,
    });

    return res.status(200).json({
      success: true,
      message: "Email OTP verified successfully",
      accessToken,
      user: safeUser(user),
    });
  } catch (error) {
    console.error("verifyEmailOtp error:", error?.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// REFRESH TOKEN (rotate refresh)
export const refreshToken = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (!token) {
      return res.status(401).json({ success: false, message: "Refresh token missing" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (err) {
      return res.status(403).json({ success: false, message: "Invalid refresh token" });
    }

    const userId = decoded.sub;
    const jti = decoded.jti;

    // check token exists in redis
    const stored = await redisClient.get(`refresh:${userId}:${jti}`);
    if (!stored || stored !== token) {
      // token is invalid, rotated or stolen
      await invalidateAllRefreshTokensForUser(userId);
      return res.status(403).json({ success: false, message: "Refresh token invalid or expired" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // generate new tokens (rotation)
    const { accessToken: newAccessToken, refreshToken: newRefreshToken, jti: newJti } = generateTokens(userId, user.phone || user.email);
    const refreshTtlSeconds = parseInt(process.env.REFRESH_TOKEN_TTL_SECONDS || 7 * 24 * 60 * 60, 10);

    // Store new refresh and delete old refresh (rotation)
    await storeRefreshToken(userId, newJti, newRefreshToken, refreshTtlSeconds);
    await redisClient.del(`refresh:${userId}:${jti}`);
    // Replace cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: refreshTtlSeconds * 1000,
      path: "/",
      domain: process.env.COOKIE_DOMAIN || undefined,
    });

    return res.json({ success: true, accessToken: newAccessToken });
  } catch (error) {
    console.error("refreshToken error:", error?.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// LOGOUT
export const logOut = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (token) {
      // decode to delete proper jti entry
      let decoded;
      try {
        decoded = jwt.decode(token);
      } catch (err) {
        decoded = null;
      }
      if (decoded && decoded.sub && decoded.jti) {
        await redisClient.del(`refresh:${decoded.sub}:${decoded.jti}`);
        await redisClient.del(`refresh_latest:${decoded.sub}`);
        // optionally delete device entry
        await redisClient.del(`device:${decoded.sub}:${decoded.jti}`);
      }
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      domain: process.env.COOKIE_DOMAIN || undefined,
    });

    return res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("logout error:", error?.message || error);
    return res.status(500).json({ success: false, message: "Logout error" });
  }
};
