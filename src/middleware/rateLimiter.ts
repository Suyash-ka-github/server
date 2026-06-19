import { Request, Response, NextFunction } from 'express';
import redis from '../utils/redis';

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60; // 15 minutes in seconds

/**
 * Rate limiter middleware for login endpoint
 * Tracks failed login attempts per IP address using atomic Redis operations
 * Blocks requests after MAX_LOGIN_ATTEMPTS within LOCKOUT_TIME
 */
export const loginRateLimiter = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // Get client IP - use req.ip which respects Express trust proxy settings
    const clientIp = req.ip || 'unknown';
    const rateLimitKey = `login-attempts:${clientIp}`;

    // Get current attempt count
    const attemptCount = await redis.get(rateLimitKey);
    const currentAttempts = parseInt(attemptCount || '0', 10);

    // Check if user is locked out
    if (currentAttempts >= MAX_LOGIN_ATTEMPTS) {
      // Get remaining TTL for Retry-After header
      const ttl = await redis.ttl(rateLimitKey);
      const retryAfter = ttl > 0 ? ttl : LOCKOUT_TIME;
      
      res.set('Retry-After', retryAfter.toString());
      return res.status(429).json({
        success: false,
        message: 'Too many login attempts',
        error: `Maximum login attempts exceeded. Please try again in ${Math.ceil(retryAfter / 60)} minutes.`
      });
    }

    // Attach helper function to response to increment failed attempts
    (res as any).incrementLoginAttempt = async () => {
      // Use atomic INCR to prevent race conditions
      const newCount = await redis.incr(rateLimitKey);
      
      // Set expiry only on first attempt
      if (newCount === 1) {
        await redis.expire(rateLimitKey, LOCKOUT_TIME);
      }
      
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
    // Don't block login on rate limiter error - graceful degradation
    next();
  }
};
