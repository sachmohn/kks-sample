import rateLimit from 'express-rate-limit';

/**
 * Brute-force login protection limiter:
 * Limits login attempts to prevent credential stuffing and brute-force attacks.
 * Defaults to 5 attempts per 15-minute window (configurable via LOGIN_RATE_LIMIT_MAX).
 * Uses express-rate-limit default key generator which handles IPv4 & IPv6 normalization safely.
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.LOGIN_RATE_LIMIT_MAX ? parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10) : 5,
  message: {
    error: 'Too many login attempts, please try again later.',
    statusCode: 429,
  },
  standardHeaders: true, // Return standard RateLimit-* headers
  legacyHeaders: false,  // Disable X-RateLimit-* headers
  statusCode: 429,
  validate: {
    xForwardedForHeader: false, // Suppress proxy warning in test environments
  },
});

/**
 * General API abuse protection limiter.
 */
export const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.GENERAL_RATE_LIMIT_MAX ? parseInt(process.env.GENERAL_RATE_LIMIT_MAX, 10) : 1000,
  message: {
    error: 'Too many requests, please slow down.',
    statusCode: 429,
  },
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  validate: {
    xForwardedForHeader: false,
  },
});
