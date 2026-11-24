import * as argon2 from 'argon2';

/**
 * Common weak password list to prevent trivial and brute-forceable passwords.
 */
const COMMON_WEAK_PASSWORDS = new Set([
  'password',
  'password123',
  '123456',
  '12345678',
  '123456789',
  'qwerty',
  'admin',
  'admin123',
  'karate',
  'karate123',
  'kka123',
  'welcome',
  'welcome1',
  'letmein',
  'student',
  'student123',
  'master',
  'master123',
  'instructor',
  'instructor123',
]);

export interface PasswordValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Weak-password policy validator:
 * - Must be at least 8 characters long
 * - Must contain at least one uppercase character
 * - Must contain at least one lowercase character
 * - Must contain at least one numeric digit
 * - Must contain at least one special character
 * - Must not be a commonly known weak password
 */
export function validatePasswordStrength(password: string): PasswordValidationResult {
  if (!password || typeof password !== 'string') {
    return { valid: false, reason: 'Password is required and must be a string' };
  }

  if (password.length < 8) {
    return { valid: false, reason: 'Password must be at least 8 characters long' };
  }

  if (COMMON_WEAK_PASSWORDS.has(password.toLowerCase())) {
    return { valid: false, reason: 'Password is too common and weak' };
  }

  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password);

  if (!hasUpperCase) {
    return { valid: false, reason: 'Password must contain at least one uppercase letter' };
  }

  if (!hasLowerCase) {
    return { valid: false, reason: 'Password must contain at least one lowercase letter' };
  }

  if (!hasDigit) {
    return { valid: false, reason: 'Password must contain at least one number' };
  }

  if (!hasSpecial) {
    return { valid: false, reason: 'Password must contain at least one special character' };
  }

  return { valid: true };
}

/**
 * Hash password using Argon2id with OWASP-recommended parameters.
 */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3,       // 3 iterations
    parallelism: 1,
  });
}

/**
 * Verify plaintext password against an Argon2id hash.
 */
export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}
