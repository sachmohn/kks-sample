import { CookieOptions, Response } from 'express';

export const REFRESH_TOKEN_COOKIE_NAME = 'refreshToken';

export interface CookieConfigOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
  maxAge?: number;
}

/**
 * Returns security-hardened cookie options for refresh tokens.
 * Enforces:
 * - HttpOnly: blocks JavaScript access to mitigate XSS token theft
 * - Secure: ensures token is transmitted over TLS/HTTPS
 * - SameSite=Strict: prevents CSRF across site contexts
 * - Path=/api/auth: limits cookie transmission strictly to auth endpoints (/refresh, /logout)
 */
export function getRefreshCookieOptions(overrides: Partial<CookieOptions> = {}): CookieOptions {
  const isSecure = process.env.COOKIE_SECURE !== 'false'; // Default to true for strict security
  const sameSite = (process.env.COOKIE_SAMESITE || 'strict') as 'strict' | 'lax' | 'none';
  const path = process.env.COOKIE_PATH || '/api/auth';

  return {
    httpOnly: true,
    secure: isSecure,
    sameSite,
    path,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
    ...overrides,
  };
}

/**
 * Set the refresh token cookie on the response.
 */
export function setRefreshTokenCookie(res: Response, token: string): void {
  res.cookie(REFRESH_TOKEN_COOKIE_NAME, token, getRefreshCookieOptions());
}

/**
 * Clear the refresh token cookie on logout or token revocation.
 */
export function clearRefreshTokenCookie(res: Response): void {
  const options = getRefreshCookieOptions();
  res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, options);
  // Also clear root path just in case clients set it at '/'
  res.clearCookie(REFRESH_TOKEN_COOKIE_NAME, { ...options, path: '/' });
}
