import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';
import { AccessTokenPayload, RefreshTokenPayload, AdminSetupTokenPayload, Role } from './types';

export const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'kka_jwt_access_secret_super_secure_key_2026_at_least_32_chars';
export const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'kka_jwt_refresh_secret_super_secure_key_2026_at_least_32_chars';
export const JWT_ADMIN_SECRET = process.env.JWT_ADMIN_SECRET || 'kka_jwt_admin_setup_secret_super_secure_key_2026_at_least_32_chars';

export const ACCESS_TOKEN_LIFETIME = '8h';       // 8h lifetime per requirements
export const ADMIN_SETUP_TOKEN_LIFETIME = '15m'; // 15m lifetime per requirements
export const REFRESH_TOKEN_LIFETIME = '7d';     // 7d lifetime

export function generateAccessToken(payload: Omit<AccessTokenPayload, 'type' | 'iat' | 'exp'>, expiresIn: string = ACCESS_TOKEN_LIFETIME): string {
  const tokenPayload: AccessTokenPayload = {
    ...payload,
    type: 'access',
  };
  return jwt.sign(tokenPayload, JWT_ACCESS_SECRET, { expiresIn: expiresIn as SignOptions['expiresIn'] });
}

export function generateRefreshToken(payload: Omit<RefreshTokenPayload, 'type' | 'iat' | 'exp'>, expiresIn: string = REFRESH_TOKEN_LIFETIME): string {
  const tokenPayload: RefreshTokenPayload = {
    ...payload,
    type: 'refresh',
  };
  return jwt.sign(tokenPayload, JWT_REFRESH_SECRET, { expiresIn: expiresIn as SignOptions['expiresIn'] });
}

export function generateAdminSetupToken(userId: string, role: Role = Role.MASTER, expiresIn: string = ADMIN_SETUP_TOKEN_LIFETIME): string {
  const tokenPayload: AdminSetupTokenPayload = {
    sub: userId,
    role,
    type: 'admin_setup',
  };
  return jwt.sign(tokenPayload, JWT_ADMIN_SECRET, { expiresIn: expiresIn as SignOptions['expiresIn'] });
}

export interface TokenVerificationResult<T> {
  valid: boolean;
  expired: boolean;
  payload?: T;
  error?: string;
}

export function verifyAccessToken(token: string): TokenVerificationResult<AccessTokenPayload> {
  try {
    const decoded = jwt.verify(token, JWT_ACCESS_SECRET) as AccessTokenPayload;
    if (decoded.type !== 'access') {
      return { valid: false, expired: false, error: 'Invalid token type' };
    }
    return { valid: true, expired: false, payload: decoded };
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      return { valid: false, expired: true, error: 'Access token has expired' };
    }
    return { valid: false, expired: false, error: err.message || 'Invalid access token' };
  }
}

export function verifyRefreshToken(token: string): TokenVerificationResult<RefreshTokenPayload> {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET) as RefreshTokenPayload;
    if (decoded.type !== 'refresh') {
      return { valid: false, expired: false, error: 'Invalid token type' };
    }
    return { valid: true, expired: false, payload: decoded };
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      return { valid: false, expired: true, error: 'Refresh token has expired' };
    }
    return { valid: false, expired: false, error: err.message || 'Invalid refresh token' };
  }
}

export function verifyAdminSetupToken(token: string): TokenVerificationResult<AdminSetupTokenPayload> {
  try {
    const decoded = jwt.verify(token, JWT_ADMIN_SECRET) as AdminSetupTokenPayload;
    if (decoded.type !== 'admin_setup') {
      return { valid: false, expired: false, error: 'Invalid token type' };
    }
    return { valid: true, expired: false, payload: decoded };
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      return { valid: false, expired: true, error: 'Admin setup token has expired' };
    }
    return { valid: false, expired: false, error: err.message || 'Invalid admin setup token' };
  }
}
