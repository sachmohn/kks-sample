import { Router, Request, Response } from 'express';
import { userRepository } from './users';
import { sessionStore } from './session';
import { verifyPassword, validatePasswordStrength } from './password';
import { setRefreshTokenCookie, clearRefreshTokenCookie, REFRESH_TOKEN_COOKIE_NAME } from './cookies';
import { generateAdminSetupToken, verifyAccessToken, verifyRefreshToken } from './jwt';
import { authenticateToken, requireRole } from './middleware';
import { Role } from './types';
import { resolvePresidentScope } from './roles';
import { loginRateLimiter } from './limiter';

export const authRouter = Router();

/**
 * Scope resolution helper for login requests.
 */
function resolveIdentifierAndRole(body: any): { identifier: string; forcedRole?: Role } | null {
  if (body.masterId) {
    return { identifier: body.masterId, forcedRole: Role.MASTER };
  }
  if (body.instructorId) {
    return { identifier: body.instructorId, forcedRole: Role.INSTRUCTOR };
  }
  if (body.studentId) {
    return { identifier: body.studentId, forcedRole: Role.STUDENT };
  }
  if (body.presidentId) {
    return { identifier: body.presidentId, forcedRole: Role.MASTER }; // President resolves to MASTER
  }

  const identifier = body.username || body.id || body.identifier;
  if (!identifier) return null;

  let forcedRole: Role | undefined;
  if (body.role) {
    try {
      forcedRole = resolvePresidentScope(body.role);
    } catch {
      // If invalid role passed, will fail role check
    }
  }

  return { identifier, forcedRole };
}

/**
 * POST /api/auth/login
 * Supports Student, Master, Instructor, and President authentication.
 * Protected with brute-force rate-limiting.
 */
authRouter.post('/login', loginRateLimiter, async (req: Request, res: Response): Promise<void> => {
  const { password } = req.body;

  const parsed = resolveIdentifierAndRole(req.body);
  if (!parsed || !password) {
    res.status(400).json({
      error: 'Missing credentials',
      message: 'Username/ID and password are required',
    });
    return;
  }

  const { identifier, forcedRole } = parsed;

  await userRepository.initialize();
  const user = userRepository.findUserByIdentifier(identifier);

  if (!user) {
    res.status(401).json({
      error: 'Invalid credentials',
      message: 'Authentication failed for the provided credentials',
    });
    return;
  }

  // Verify password using Argon2id
  const isPasswordValid = await verifyPassword(user.passwordHash, password);
  if (!isPasswordValid) {
    res.status(401).json({
      error: 'Invalid credentials',
      message: 'Authentication failed for the provided credentials',
    });
    return;
  }

  // If a specific role was requested or enforced, ensure matching (with President scope resolution)
  const effectiveRole = user.role;
  if (forcedRole && forcedRole !== effectiveRole) {
    res.status(401).json({
      error: 'Role mismatch',
      message: `User is not authorized for requested role ${forcedRole}`,
    });
    return;
  }

  // Create session with token family tracking
  const { tokens } = sessionStore.createSession(user.id, user.username, effectiveRole);

  // Set secure HTTP-only cookie with Path=/api/auth, HttpOnly, Secure, SameSite=Strict
  setRefreshTokenCookie(res, tokens.refreshToken);

  res.status(200).json({
    message: 'Login successful',
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    user: {
      id: user.id,
      username: user.username,
      role: effectiveRole,
      name: user.name,
    },
  });
});

/**
 * POST /api/auth/refresh
 * Refresh token rotation (RTR) with replay attack detection.
 */
authRouter.post('/refresh', async (req: Request, res: Response): Promise<void> => {
  const refreshToken =
    req.cookies?.[REFRESH_TOKEN_COOKIE_NAME] ||
    req.body?.refreshToken ||
    req.headers['x-refresh-token'];

  if (!refreshToken || typeof refreshToken !== 'string') {
    res.status(401).json({
      error: 'Refresh token required',
      message: 'No refresh token provided in cookies or request body',
    });
    return;
  }

  await userRepository.initialize();
  const result = sessionStore.rotateRefreshToken(refreshToken, (userId) => {
    return userRepository.getUserById(userId)?.username || userId;
  });

  if (!result.success) {
    // If replay attack was detected or token is invalid, clear cookie
    clearRefreshTokenCookie(res);
    res.status(result.statusCode).json({
      error: result.error,
      code: result.replayDetected ? 'REPLAY_ATTACK_DETECTED' : 'INVALID_REFRESH_TOKEN',
    });
    return;
  }

  // Set newly rotated refresh token in secure cookie
  setRefreshTokenCookie(res, result.tokens!.refreshToken);

  res.status(200).json({
    message: 'Token rotated successfully',
    accessToken: result.tokens!.accessToken,
    refreshToken: result.tokens!.refreshToken,
  });
});

/**
 * POST /api/auth/logout
 * Server-side session revocation for Student, Master, and Instructor.
 */
authRouter.post('/logout', async (req: Request, res: Response): Promise<void> => {
  // 1. Try to extract from Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    const verification = verifyAccessToken(token);
    if (verification.valid && verification.payload) {
      const sessionId = verification.payload.sessionId || verification.payload.familyId;
      if (sessionId) {
        sessionStore.revokeFamily(sessionId, 'LOGOUT');
      }
    }
  }

  // 2. Try to extract from Refresh Token (cookie or body)
  const refreshToken =
    req.cookies?.[REFRESH_TOKEN_COOKIE_NAME] ||
    req.body?.refreshToken;

  if (refreshToken && typeof refreshToken === 'string') {
    const refreshVerification = verifyRefreshToken(refreshToken);
    if (refreshVerification.payload?.familyId) {
      sessionStore.revokeFamily(refreshVerification.payload.familyId, 'LOGOUT');
    }
  }

  // 3. Clear cookie
  clearRefreshTokenCookie(res);

  res.status(200).json({
    message: 'Logged out successfully',
  });
});

/**
 * POST /api/auth/admin-setup-token
 * Generates an admin setup token with a 15-minute lifetime.
 */
authRouter.post('/admin-setup-token', authenticateToken, requireRole(Role.MASTER), (req: Request, res: Response): void => {
  const token = generateAdminSetupToken(req.user!.sub, req.user!.role);
  res.status(200).json({
    message: 'Admin setup token generated',
    adminSetupToken: token,
    expiresIn: '15m',
  });
});

/**
 * GET /api/auth/client-ip
 * Utility to verify trusted proxy IP extraction.
 */
authRouter.get('/client-ip', (req: Request, res: Response): void => {
  res.status(200).json({
    ip: req.ip,
    ips: req.ips,
    remoteAddress: req.socket.remoteAddress,
    xForwardedFor: req.headers['x-forwarded-for'],
    trustProxy: req.app.get('trust proxy'),
  });
});
