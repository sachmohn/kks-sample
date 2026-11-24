import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from './jwt';
import { sessionStore } from './session';
import { AccessTokenPayload, Role } from './types';

// Extend Express Request interface to include authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: AccessTokenPayload;
      token?: string;
    }
  }
}

/**
 * Authentication middleware:
 * Validates JWT access token from Authorization header (Bearer schema).
 * Verifies signature, expiration, and checks server-side session revocation.
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  let token: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else if (req.headers['x-access-token']) {
    token = String(req.headers['x-access-token']).trim();
  }

  if (!token) {
    res.status(401).json({
      error: 'Access token required',
      message: 'Authorization header with Bearer token is missing',
    });
    return;
  }

  const verification = verifyAccessToken(token);

  if (!verification.valid) {
    if (verification.expired) {
      res.status(401).json({
        error: 'Token expired',
        message: 'Access token has expired',
      });
      return;
    }

    res.status(401).json({
      error: 'Invalid token',
      message: verification.error || 'Token verification failed or token was tampered with',
    });
    return;
  }

  const payload = verification.payload!;

  // Server-side session revocation check (supports logout and replay attack invalidation)
  const sessionId = payload.sessionId || payload.familyId;
  if (sessionId && sessionStore.isRevoked(sessionId)) {
    res.status(401).json({
      error: 'Token has been revoked',
      message: 'The session for this token has been revoked or logged out',
    });
    return;
  }

  req.user = payload;
  req.token = token;
  next();
}

/**
 * Role-based authorization middleware:
 * Enforces role requirement strictly on protected endpoints.
 * Returns 401/403 if the user does not possess the required role.
 */
export function requireRole(requiredRole: Role) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User must be authenticated before checking role',
      });
      return;
    }

    if (req.user.role !== requiredRole) {
      const statusCode = process.env.ROLE_REJECTION_STATUS === '403' ? 403 : 401;
      res.status(statusCode).json({
        error: 'Forbidden: insufficient role permissions',
        message: `Access denied. Endpoint requires role ${requiredRole}, but user has role ${req.user.role}`,
        requiredRole,
        userRole: req.user.role,
      });
      return;
    }

    next();
  };
}
