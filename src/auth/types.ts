/**
 * Khan's Karate Academy (KKA) Authentication & Authorization Types
 */

export enum Role {
  STUDENT = 'STUDENT',
  MASTER = 'MASTER',
  INSTRUCTOR = 'INSTRUCTOR',
}

/**
 * President Scope Resolution:
 * Within Khan's Karate Academy (KKA), the President is the executive authority / Grandmaster.
 * The academy's canonical RBAC model defines three primary roles: STUDENT, INSTRUCTOR, MASTER.
 * The President's authorization scope resolves directly to the 'MASTER' role,
 * granting full administrative, instructional, and operational access across the entire academy system.
 */
export const PRESIDENT_SCOPE_RESOLUTION = Role.MASTER;

export interface User {
  id: string;
  username: string;
  role: Role;
  passwordHash: string;
  name?: string;
  masterId?: string;
  instructorId?: string;
  studentId?: string;
  presidentId?: string;
}

export interface AccessTokenPayload {
  sub: string;
  username: string;
  role: Role;
  sessionId: string;
  familyId: string;
  type: 'access';
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  sub: string;
  familyId: string;
  tokenId: string;
  type: 'refresh';
  iat?: number;
  exp?: number;
}

export interface AdminSetupTokenPayload {
  sub: string;
  role: Role;
  type: 'admin_setup';
  iat?: number;
  exp?: number;
}

export interface TokenFamily {
  familyId: string;
  userId: string;
  role: Role;
  activeTokenId: string;
  usedTokenIds: Set<string>;
  isRevoked: boolean;
  revocationReason?: string;
  createdAt: number;
  updatedAt: number;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}
