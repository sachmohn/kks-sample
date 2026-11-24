import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from './jwt';
import { sessionStore } from './session';
import { Role } from './types';

// Extend Express Request interface to include authenticated user details
declare global {
  namespace Express {
    interface Request {
      user?: {
        sub: string;
        username: string;
        role: Role;
        familyId?: string;
      };
    }
  }
}

/**
 * Token authentication middleware:
 * Extracts Bearer token from the Authorization header and verifies it.
 * Verifies that the associated session has not been revoked.
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Access token is missing or malformed',
    });
    return;
  }

  const result = verifyAccessToken(token);

  if (result.expired) {
    res.status(401).json({
      error: 'Token expired',
      message: 'Access token has expired',
    });
    return;
  }

  if (!result.valid || !result.payload) {
    res.status(401).json({
      error: 'Invalid token',
      message: 'Access token signature or format is invalid',
    });
    return;
  }

  const payload = result.payload;

  // Check if session has been revoked (e.g. after logout or replay attack detection)
  if (payload.familyId && sessionStore.isRevoked(payload.familyId)) {
    res.status(401).json({
      error: 'Token has been revoked',
      message: 'The session for this token has been revoked or logged out',
    });
    return;
  }

  req.user = {
    sub: payload.sub,
    username: payload.username,
    role: payload.role,
    familyId: payload.familyId,
  };

  next();
}

/**
 * Role-based authorization middleware:
 * Enforces role requirement strictly on protected endpoints.
 * Supports a single Role or an array of allowed Roles.
 * Returns 401/403 if the user does not possess an allowed role.
 */
export function requireRole(requiredRole: Role | Role[]) {
  const allowedRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        message: 'User must be authenticated before checking role',
      });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      const statusCode = process.env.ROLE_REJECTION_STATUS === '403' ? 403 : 401;
      res.status(statusCode).json({
        error: 'Forbidden: insufficient role permissions',
        message: `Access denied. Endpoint requires role ${allowedRoles.join(' or ')}, but user has role ${req.user.role}`,
        requiredRole,
        userRole: req.user.role,
      });
      return;
    }

    next();
  };
}
