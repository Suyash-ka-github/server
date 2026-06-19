import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60; // 15 minutes in seconds

/**
 * Rate limiter middleware for login endpoint
 * Tracks failed login attempts per IP address
 * Blocks requests after MAX_LOGIN_ATTEMPTS within LOCKOUT_TIME
 */
export const loginRateLimiter = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // Get client IP (handles proxies)
    const clientIp =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() ||
      req.socket.remoteAddress ||
      'unknown';

    const rateLimitKey = `login-attempts:${clientIp}`;

    // Get current attempt count
    const attemptCount = await redis.get(rateLimitKey);
    const currentAttempts = parseInt(attemptCount || '0', 10);

    // Check if user is locked out
    if (currentAttempts >= MAX_LOGIN_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: 'Too many login attempts',
        error: `Maximum login attempts exceeded. Please try again in ${LOCKOUT_TIME / 60} minutes.`
      });
    }

    // Attach helper function to response to increment failed attempts
    (res as any).incrementLoginAttempt = async () => {
      const newCount = currentAttempts + 1;
      await redis.setex(rateLimitKey, LOCKOUT_TIME, newCount.toString());
      console.log(`[Rate Limiter] Login attempt ${newCount}/${MAX_LOGIN_ATTEMPTS} from IP: ${clientIp}`);
    };

    // Attach helper function to clear attempts on successful login
    (res as any).clearLoginAttempts = async () => {
      await redis.del(rateLimitKey);
      console.log(`[Rate Limiter] Login attempts cleared for IP: ${clientIp}`);
    };

    // Store IP for logging
    (req as any).clientIp = clientIp;

    next();
  } catch (error) {
    console.error('Rate limiter error:', error);
    // Don't block login on rate limiter error
    next();
  }
};
