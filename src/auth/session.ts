import { randomUUID } from 'crypto';
import { Role, TokenFamily, AuthTokens } from './types';
import { generateAccessToken, generateRefreshToken, verifyRefreshToken } from './jwt';

export class SessionStore {
  private families: Map<string, TokenFamily> = new Map();
  private revokedSessionIds: Set<string> = new Set();
  private userToFamilies: Map<string, Set<string>> = new Map();

  /**
   * Create a new token family and session upon login.
   */
  public createSession(userId: string, username: string, role: Role): { tokens: AuthTokens; familyId: string } {
    const familyId = randomUUID();
    const tokenId = randomUUID();
    const now = Date.now();

    const family: TokenFamily = {
      familyId,
      userId,
      role,
      activeTokenId: tokenId,
      usedTokenIds: new Set(),
      isRevoked: false,
      createdAt: now,
      updatedAt: now,
    };

    this.families.set(familyId, family);

    if (!this.userToFamilies.has(userId)) {
      this.userToFamilies.set(userId, new Set());
    }
    this.userToFamilies.get(userId)!.add(familyId);

    const accessToken = generateAccessToken({
      sub: userId,
      username,
      role,
      sessionId: familyId,
      familyId,
    });

    const refreshToken = generateRefreshToken({
      sub: userId,
      familyId,
      tokenId,
    });

    return {
      tokens: { accessToken, refreshToken },
      familyId,
    };
  }

  /**
   * Check if a session/family is revoked.
   */
  public isRevoked(familyOrSessionId: string): boolean {
    if (this.revokedSessionIds.has(familyOrSessionId)) {
      return true;
    }
    const family = this.families.get(familyOrSessionId);
    if (!family) {
      return false; // If not in map, might be stateless or expired
    }
    return family.isRevoked;
  }

  /**
   * Revoke a specific token family / session (e.g. on logout).
   */
  public revokeFamily(familyId: string, reason: string = 'LOGOUT'): boolean {
    this.revokedSessionIds.add(familyId);
    const family = this.families.get(familyId);
    if (family) {
      family.isRevoked = true;
      family.revocationReason = reason;
      family.updatedAt = Date.now();
      return true;
    }
    return true; // Still marked in revokedSessionIds
  }

  /**
   * Revoke all active sessions for a given user.
   */
  public revokeUserSessions(userId: string, reason: string = 'LOGOUT'): void {
    const familyIds = this.userToFamilies.get(userId);
    if (familyIds) {
      for (const familyId of familyIds) {
        this.revokeFamily(familyId, reason);
      }
    }
  }

  /**
   * Rotate a refresh token with token family tracking and replay attack detection.
   */
  public rotateRefreshToken(oldRefreshTokenString: string, usernameLookup?: (userId: string) => string): {
    success: boolean;
    tokens?: AuthTokens;
    error?: string;
    statusCode: number;
    replayDetected?: boolean;
  } {
    const verification = verifyRefreshToken(oldRefreshTokenString);

    if (!verification.valid) {
      if (verification.expired) {
        return { success: false, error: 'Refresh token has expired', statusCode: 401 };
      }
      return { success: false, error: verification.error || 'Invalid refresh token', statusCode: 401 };
    }

    const payload = verification.payload!;
    const { familyId, tokenId, sub: userId } = payload;

    const family = this.families.get(familyId);

    if (!family) {
      return { success: false, error: 'Session not found or expired', statusCode: 401 };
    }

    // Check if family was already revoked
    if (family.isRevoked || this.revokedSessionIds.has(familyId)) {
      return {
        success: false,
        error: `Token family revoked (${family.revocationReason || 'REVOKED'})`,
        statusCode: 401,
      };
    }

    // Replay attack detection:
    // If presented token ID is in usedTokenIds OR is not the current activeTokenId
    if (family.usedTokenIds.has(tokenId) || family.activeTokenId !== tokenId) {
      // REPLAY DETECTED: Immediately invalidate the entire family to prevent account takeover!
      family.isRevoked = true;
      family.revocationReason = 'REPLAY_ATTACK_DETECTED';
      family.updatedAt = Date.now();
      this.revokedSessionIds.add(familyId);

      return {
        success: false,
        error: 'Replay attack detected: compromised token family has been revoked',
        statusCode: 401,
        replayDetected: true,
      };
    }

    // Legitimate rotation:
    // 1. Move old active token to used
    family.usedTokenIds.add(tokenId);

    // 2. Generate new active token ID
    const newTokenId = randomUUID();
    family.activeTokenId = newTokenId;
    family.updatedAt = Date.now();

    const username = usernameLookup ? usernameLookup(userId) : `user_${userId}`;

    // 3. Generate new tokens
    const newAccessToken = generateAccessToken({
      sub: userId,
      username,
      role: family.role,
      sessionId: familyId,
      familyId,
    });

    const newRefreshToken = generateRefreshToken({
      sub: userId,
      familyId,
      tokenId: newTokenId,
    });

    return {
      success: true,
      tokens: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      },
      statusCode: 200,
    };
  }

  public getFamily(familyId: string): TokenFamily | undefined {
    return this.families.get(familyId);
  }

  public clear(): void {
    this.families.clear();
    this.revokedSessionIds.clear();
    this.userToFamilies.clear();
  }
}

export const sessionStore = new SessionStore();
