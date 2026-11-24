import { Role, PRESIDENT_SCOPE_RESOLUTION } from './types';

/**
 * Scope Clarification & President Scope Resolution:
 * 
 * In Khan's Karate Academy (KKA), the President serves as the executive leader
 * and highest martial authority.
 * 
 * Scope Resolution Rule:
 * Any identity or scope tagged as 'PRESIDENT' resolves directly to the 'MASTER' role.
 * This guarantees that the President holds all permissions and administrative capabilities
 * granted to the Master role, while avoiding arbitrary permission fragmentation.
 */

export function resolvePresidentScope(scopeOrRole: string): Role {
  if (!scopeOrRole) {
    throw new Error('Scope or role string must be provided');
  }

  const normalized = scopeOrRole.trim().toUpperCase();

  if (normalized === 'PRESIDENT') {
    return PRESIDENT_SCOPE_RESOLUTION; // Resolves to Role.MASTER
  }

  if (normalized === Role.STUDENT) {
    return Role.STUDENT;
  }

  if (normalized === Role.INSTRUCTOR) {
    return Role.INSTRUCTOR;
  }

  if (normalized === Role.MASTER) {
    return Role.MASTER;
  }

  throw new Error(`Unknown role or scope: "${scopeOrRole}". Valid roles are STUDENT, INSTRUCTOR, MASTER, or PRESIDENT.`);
}

export function isAuthorizedForRole(userRole: Role, requiredRole: Role): boolean {
  return userRole === requiredRole;
}
