import { Request, Response, NextFunction } from 'express';
import redis from '../utils/redis';

/**
 * Email-based rate limiter middleware for login endpoint
 * Protects against brute force attacks on specific user accounts
 * 
 * Configuration (via environment variables):
 * - LOGIN_ATTEMPT_MAX: Maximum failed login attempts allowed within window (default: 5)
 * - LOGIN_ATTEMPT_WINDOW: Time window in seconds to track attempts (default: 60 = 1 minute)
 * - LOGIN_COOLDOWN_DURATION: Lockout duration in seconds after exceeding max attempts (default: 600 = 10 minutes)
 * 
 * Behavior:
 * - Tracks failed login attempts per email/username identifier
 * - If user fails MAX attempts within WINDOW seconds → lock account for COOLDOWN seconds
 * - Uses atomic Redis INCR to prevent race conditions in high concurrency
 * - After cooldown expires, counter resets and user can try again
 * 
 * Edge Cases Handled:
 * - Concurrent requests: Atomic INCR prevents lost increments from simultaneous requests
 * - Window expiry: TTL auto-expires counter after WINDOW seconds
 * - Cooldown expiry: TTL auto-expires cooldown lock after COOLDOWN seconds
 * - Missing identifier: Passes through to next middleware (no rate limiting)
 * - Redis failures: Graceful degradation - logs error but allows login attempt
 */
export const emailRateLimiter = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // Load configuration from environment variables
    const MAX_LOGIN_ATTEMPTS = parseInt(process.env.LOGIN_ATTEMPT_MAX || '5', 10);
    const ATTEMPT_WINDOW = parseInt(process.env.LOGIN_ATTEMPT_WINDOW || '60', 10); // seconds
    const COOLDOWN_PERIOD = parseInt(process.env.LOGIN_COOLDOWN_DURATION || '600', 10); // seconds

    const { identifier } = req.body;

    // Skip rate limiting if identifier not provided
    if (!identifier) {
      return next();
    }

    const rateLimitKey = `login-attempts:${identifier}`;
    const cooldownKey = `login-cooldown:${identifier}`;

    // ==================== EDGE CASE 1: Concurrent Request During Cooldown ====================
    // Multiple requests arriving simultaneously while account is locked
    // Solution: Atomic GET prevents race conditions - all requests see same cooldown status
    const isOnCooldown = await redis.get(cooldownKey);
    if (isOnCooldown) {
      return res.status(401).json({
        success: false,
        message: 'Authentication failed',
        error: 'Invalid credentials'
      });
    }

    // ==================== EDGE CASE 2: Window Period Rollover ====================
    // Problem: What if window is 60 seconds and requests arrive at seconds 50, 55, 65?
    // Second 50 & 55: Within window, count increases
    // Second 65: Old count expired, new window starts
    // Solution: TTL (expire) ensures counter resets after ATTEMPT_WINDOW seconds automatically
    const attemptCount = await redis.get(rateLimitKey);
    const currentAttempts = parseInt(attemptCount || '0', 10);

    // Check if current attempt count exceeds maximum
    if (currentAttempts >= MAX_LOGIN_ATTEMPTS) {
      // Account needs cooldown
      await redis.setex(cooldownKey, COOLDOWN_PERIOD, 'locked');
      console.log(`[Rate Limiter] Account locked: ${identifier} | Cooldown: ${COOLDOWN_PERIOD}s`);

      return res.status(401).json({
        success: false,
        message: 'Authentication failed',
        error: 'Invalid credentials'
      });
    }

    // ==================== EDGE CASE 3: Concurrent Increment Requests ====================
    // Problem: Two requests arrive simultaneously, both read count=4, both increment to 5
    // Result: We lose one increment and need 6 attempts instead of 5 to trigger lockout
    // Solution: Use atomic INCR operation instead of GET -> increment -> SET
    // INCR is atomic at Redis level, guarantees no lost increments
    (res as any).incrementEmailAttempt = async () => {
      const newCount = await redis.incr(rateLimitKey);

      // Only set expiry on first attempt (INCR returns 1 on first call)
      if (newCount === 1) {
        await redis.expire(rateLimitKey, ATTEMPT_WINDOW);
        console.log(`[Rate Limiter] New window: ${identifier} | Window duration: ${ATTEMPT_WINDOW}s`);
      }

      // When max attempts reached, trigger cooldown for future requests
      if (newCount >= MAX_LOGIN_ATTEMPTS) {
        await redis.setex(cooldownKey, COOLDOWN_PERIOD, 'locked');
        console.log(`[Rate Limiter] Max attempts reached: ${identifier} (${newCount}/${MAX_LOGIN_ATTEMPTS}) | Locked for ${COOLDOWN_PERIOD}s`);
      } else {
        console.log(`[Rate Limiter] Failed attempt: ${identifier} (${newCount}/${MAX_LOGIN_ATTEMPTS})`);
      }
    };

    // Clear attempts on successful login
    (res as any).clearEmailAttempts = async () => {
      await redis.del(rateLimitKey);
      console.log(`[Rate Limiter] Attempts cleared: ${identifier} (successful login)`);
    };

    next();
  } catch (error) {
    console.error('[Rate Limiter] Error:', error);
    // Graceful degradation: If Redis fails, don't block login
    // Log the error but allow request to proceed
    next();
  }
};
