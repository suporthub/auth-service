import { Request, Response, NextFunction } from 'express';
import { getRedis } from '../lib/redis';

interface RateLimitOptions {
  windowSeconds: number;
  max: number;
  keyFn: (req: Request) => string | null | undefined;
  message?: string;
}

/**
 * Redis-backed sliding window rate limiter.
 * More accurate than express-rate-limit's in-memory counter
 * because it works across multiple service instances.
 */
export function redisRateLimit(opts: RateLimitOptions) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const keySuffix = opts.keyFn(req);
    
    // Skip this limiter layer if no key was generated (e.g., missing fingerprint or email)
    if (!keySuffix) {
      next();
      return;
    }

    const redis = getRedis();
    const key = `rl:${keySuffix}`;
    const now = Date.now();
    const windowStart = now - opts.windowSeconds * 1000;

    // Sliding window: remove old timestamps, add current, count remaining
    const results = await redis
      .multi()
      .zremrangebyscore(key, '-inf', windowStart)
      .zadd(key, now, `${now}-${Math.random()}`)
      .zcard(key)
      .expire(key, opts.windowSeconds)
      .exec();

    const cardResult = results?.[2] as [Error | null, number] | null;
    const count: number = cardResult?.[1] ?? 0;
    const remaining = opts.max - count;

    res.setHeader('X-RateLimit-Limit', opts.max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, remaining));

    if (remaining < 0) {
      res.status(429).json({
        success: false,
        message: opts.message ?? 'Too many requests. Please try again later.',
        retryAfter: opts.windowSeconds,
      });
      return;
    }

    next();
  };
}

// ── Pre-configured rate limiters ──────────────────────────────────────────────

export const loginRateLimit = [
  // Layer 1: IP Limit (Broad)
  redisRateLimit({
    windowSeconds: 15 * 60,
    max: 100, // Reverted to higher development limits
    keyFn: (req) => `login:ip:${req.ip}`,
    message: 'Too many login attempts from this network. Please wait 15 minutes.',
  }),
  // Layer 2: Device Fingerprint Limit (Strict)
  redisRateLimit({
    windowSeconds: 15 * 60,
    max: 20,
    keyFn: (req) => {
      const fp = req.headers['x-device-fingerprint'];
      return typeof fp === 'string' && fp.trim().length > 0 ? `login:device:${fp}` : null;
    },
    message: 'Too many login attempts from this device. Please wait 15 minutes.',
  }),
  // Layer 3: Account Identifier Limit (Strictest)
  redisRateLimit({
    windowSeconds: 15 * 60,
    max: 10,
    keyFn: (req) => {
      const email = req.body?.email;
      return typeof email === 'string' && email.trim().length > 0 ? `login:email:${email}` : null;
    },
    message: 'Too many login attempts for this account. Please wait 15 minutes.',
  }),
];

export const registerRateLimit = [
  // Layer 1: IP Limit
  redisRateLimit({
    windowSeconds: 60 * 60,
    max: 100,
    keyFn: (req) => `register:ip:${req.ip}`,
    message: 'Too many registration attempts from this network. Please wait 1 hour.',
  }),
  // Layer 2: Device Fingerprint Limit
  redisRateLimit({
    windowSeconds: 60 * 60,
    max: 10,
    keyFn: (req) => {
      const fp = req.headers['x-device-fingerprint'];
      return typeof fp === 'string' && fp.trim().length > 0 ? `register:device:${fp}` : null;
    },
    message: 'Too many registration attempts from this device. Please wait 1 hour.',
  }),
];

export const otpSendRateLimit = [
  // Layer 1: IP Limit
  redisRateLimit({
    windowSeconds: 10 * 60,
    max: 100,
    keyFn: (req) => `otp_send:ip:${req.ip}`,
    message: 'Too many OTP requests from this network. Please wait 10 minutes.',
  }),
  // Layer 2: Device Fingerprint Limit
  redisRateLimit({
    windowSeconds: 10 * 60,
    max: 20,
    keyFn: (req) => {
      const fp = req.headers['x-device-fingerprint'];
      return typeof fp === 'string' && fp.trim().length > 0 ? `otp_send:device:${fp}` : null;
    },
    message: 'Too many OTP requests from this device. Please wait 10 minutes.',
  }),
  // Layer 3: User Identifier Limit
  redisRateLimit({
    windowSeconds: 10 * 60,
    max: 10,
    keyFn: (req) => {
      const id = req.body?.email || req.body?.phone;
      return typeof id === 'string' && id.trim().length > 0 ? `otp_send:id:${id}` : null;
    },
    message: 'Too many OTP requests for this account. Please wait 10 minutes.',
  }),
];

export const totpRateLimit = [
  // Layer 1: IP Limit
  redisRateLimit({
    windowSeconds: 5 * 60,
    max: 100,
    keyFn: (req) => `totp:ip:${req.ip}`,
    message: 'Too many TOTP attempts from this network. Please wait 5 minutes.',
  }),
  // Layer 2: Device Fingerprint Limit
  redisRateLimit({
    windowSeconds: 5 * 60,
    max: 20,
    keyFn: (req) => {
      const fp = req.headers['x-device-fingerprint'];
      return typeof fp === 'string' && fp.trim().length > 0 ? `totp:device:${fp}` : null;
    },
    message: 'Too many TOTP attempts from this device. Please wait 5 minutes.',
  }),
];
