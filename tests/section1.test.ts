import * as fs from 'fs';
import * as path from 'path';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { app } from '../src/app';
import { userRepository } from '../src/auth/users';
import { sessionStore } from '../src/auth/session';
import { resolvePresidentScope } from '../src/auth/roles';
import { Role, PRESIDENT_SCOPE_RESOLUTION } from '../src/auth/types';
import { hashPassword, verifyPassword, validatePasswordStrength } from '../src/auth/password';
import {
  generateAccessToken,
  generateRefreshToken,
  generateAdminSetupToken,
  verifyAdminSetupToken,
} from '../src/auth/jwt';

const AUDIT_LOG_PATH = path.join(__dirname, 'audit_evidence.log');
const SENSITIVE_KEY_PATTERN = /^(accessToken|refreshToken|adminSetupToken|password|passwordHash|secret)$/i;

function redactSensitiveString(input: string): string {
  return input
    .replace(/(refreshToken=)([^;\s]+)/gi, '$1[REDACTED_TOKEN]')
    .replace(/(Bearer\s+)[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi, '$1[REDACTED_JWT]')
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED_JWT]')
    .replace(/\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[^\s"']+/g, '$argon2id$v=19$m=65536,t=3,p=1$[REDACTED_SALT_AND_HASH]');
}

function redactSensitiveData(value: unknown): unknown {
  if (typeof value === 'string') {
    return redactSensitiveString(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveData(item));
  }
  if (typeof value === 'object' && value !== null) {
    const sanitized: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      if (SENSITIVE_KEY_PATTERN.test(key) && typeof val === 'string') {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = redactSensitiveData(val);
      }
    }
    return sanitized;
  }
  return value;
}

// Helper to format, redact, and persist HTTP/security audit evidence
function logEvidence(taskNumber: number, taskTitle: string, data: Record<string, any>) {
  const redactedData = redactSensitiveData(data) as Record<string, unknown>;
  const lines: string[] = [
    '',
    '======================================================================',
    `[AUDIT EVIDENCE - TASK ${taskNumber}] ${taskTitle}`,
    '======================================================================',
  ];

  for (const [key, val] of Object.entries(redactedData)) {
    if (typeof val === 'object' && val !== null) {
      lines.push(`--- ${key} ---`);
      lines.push(JSON.stringify(val, null, 2));
    } else {
      lines.push(`${key}: ${val}`);
    }
  }
  lines.push('======================================================================');
  lines.push('');

  const block = lines.join('\n');
  fs.appendFileSync(AUDIT_LOG_PATH, block, 'utf8');
  console.log(block);
}

describe('KKA Section 1 Security Audit Test Suite', () => {
  beforeAll(async () => {
    await userRepository.initialize();
    const header = [
      'KKA SECTION 1 SECURITY AUDIT RUNTIME EVIDENCE (REDACTED)',
      `Generated At: ${new Date().toISOString()}`,
      'Policy: Option 2 (src/ unmodified) + R5 (Zero exposed secrets/tokens)',
      '======================================================================',
      '',
    ].join('\n');
    fs.writeFileSync(AUDIT_LOG_PATH, header, 'utf8');
  });

  beforeEach(() => {
    sessionStore.clear();
  });

  /**
   * Task 1: Confirm President role scope resolution in code.
   */
  test('Task 1: Confirm President role scope resolution in code', async () => {
    // 1. Static code resolution check
    const resolvedRole = resolvePresidentScope('PRESIDENT');
    expect(resolvedRole).toBe(Role.MASTER);
    expect(PRESIDENT_SCOPE_RESOLUTION).toBe(Role.MASTER);

    // 2. Authentication with President credentials
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.1.10')
      .send({ presidentId: 'PRESIDENT-001', password: 'StrongP@ssw0rd!' });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.user.role).toBe(Role.MASTER);
    const presidentAccessToken = loginRes.body.accessToken;
    expect(presidentAccessToken).toBeDefined();

    // 3. Verify Master dashboard access with President's token
    const masterDashRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${presidentAccessToken}`);

    expect(masterDashRes.status).toBe(200);
    expect(masterDashRes.body.role).toBe(Role.MASTER);
    expect(masterDashRes.body.message).toBe('Welcome to the Master Dashboard');

    logEvidence(1, 'Confirm President role scope resolution in code', {
      staticScopeResolution: `resolvePresidentScope('PRESIDENT') -> ${resolvedRole}`,
      constantMapping: `PRESIDENT_SCOPE_RESOLUTION -> ${PRESIDENT_SCOPE_RESOLUTION}`,
      loginResponseStatus: loginRes.status,
      loginResponseBody: {
        ...loginRes.body,
        accessToken: '[REDACTED]',
        refreshToken: '[REDACTED]',
      },
      masterDashboardStatus: masterDashRes.status,
      masterDashboardBody: masterDashRes.body,
    });
  });

  /**
   * Task 2: Wrong-role JWT rejection (returns 401).
   */
  test('Task 2: Wrong-role JWT rejection (returns 401)', async () => {
    // Obtain tokens for STUDENT and INSTRUCTOR
    const studentLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.2.10')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    const studentToken = studentLogin.body.accessToken;

    const instructorLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.2.20')
      .send({ instructorId: 'INSTRUCTOR-001', password: 'StrongP@ssw0rd!' });
    const instructorToken = instructorLogin.body.accessToken;

    // Student attempts to access Master dashboard
    const studentToMasterRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${studentToken}`);
    expect(studentToMasterRes.status).toBe(401);

    // Student attempts to access Instructor dashboard
    const studentToInstructorRes = await request(app)
      .get('/api/instructor/dashboard')
      .set('Authorization', `Bearer ${studentToken}`);
    expect(studentToInstructorRes.status).toBe(401);

    // Instructor attempts to access Master dashboard
    const instructorToMasterRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${instructorToken}`);
    expect(instructorToMasterRes.status).toBe(401);

    logEvidence(2, 'Wrong-role JWT rejection (returns 401)', {
      studentToMaster: {
        statusCode: studentToMasterRes.status,
        headers: studentToMasterRes.headers,
        body: studentToMasterRes.body,
      },
      studentToInstructor: {
        statusCode: studentToInstructorRes.status,
        headers: studentToInstructorRes.headers,
        body: studentToInstructorRes.body,
      },
      instructorToMaster: {
        statusCode: instructorToMasterRes.status,
        headers: instructorToMasterRes.headers,
        body: instructorToMasterRes.body,
      },
    });
  });

  /**
   * Task 3: Expired JWT rejection (returns 401).
   */
  test('Task 3: Expired JWT rejection (returns 401)', async () => {
    const expiredToken = generateAccessToken(
      {
        sub: 'student-001',
        username: 'student1',
        role: Role.STUDENT,
        sessionId: 'expired-session-123',
        familyId: 'expired-family-123',
      },
      '-5s'
    );

    const expiredRes = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(expiredRes.status).toBe(401);
    expect(expiredRes.body.error).toBe('Token expired');

    logEvidence(3, 'Expired JWT rejection (returns 401)', {
      rawHttpStatus: expiredRes.status,
      rawHttpHeaders: expiredRes.headers,
      rawHttpBody: expiredRes.body,
    });
  });

  /**
   * Task 4: Tampered JWT rejection (returns 401).
   */
  test('Task 4: Tampered JWT rejection (returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.4.10')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    const originalToken = loginRes.body.accessToken;

    // Tamper with payload (elevate role from STUDENT to MASTER)
    const tokenParts = originalToken.split('.');
    const decodedPayload = JSON.parse(Buffer.from(tokenParts[1], 'base64url').toString('utf8'));
    decodedPayload.role = 'MASTER';
    decodedPayload.sub = 'master-001';
    const tamperedPayload = Buffer.from(JSON.stringify(decodedPayload)).toString('base64url');
    const tamperedToken = `${tokenParts[0]}.${tamperedPayload}.${tokenParts[2]}`;

    // Tamper with signature
    const corruptSignatureToken = `${tokenParts[0]}.${tokenParts[1]}.CORRUPTED_SIGNATURE_BYTES`;

    const tamperedPayloadRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${tamperedToken}`);

    expect(tamperedPayloadRes.status).toBe(401);
    expect(tamperedPayloadRes.body.error).toBe('Invalid token');

    const corruptSigRes = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${corruptSignatureToken}`);

    expect(corruptSigRes.status).toBe(401);
    expect(corruptSigRes.body.error).toBe('Invalid token');

    logEvidence(4, 'Tampered JWT rejection (returns 401)', {
      tamperedPayloadRequest: {
        status: tamperedPayloadRes.status,
        headers: tamperedPayloadRes.headers,
        body: tamperedPayloadRes.body,
      },
      corruptSignatureRequest: {
        status: corruptSigRes.status,
        headers: corruptSigRes.headers,
        body: corruptSigRes.body,
      },
    });
  });

  /**
   * Task 5: Brute-force protection test (triggers 429 Too Many Requests).
   */
  test('Task 5: Brute-force protection test (triggers 429 Too Many Requests)', async () => {
    const clientIp = '198.51.100.99';
    const responses: any[] = [];
    let rateLimitTriggeredRes: any = null;

    // Send rapid failed login attempts from clientIp until 429 is triggered
    for (let attempt = 1; attempt <= 8; attempt++) {
      const res = await request(app)
        .post('/api/auth/login')
        .set('X-Forwarded-For', clientIp)
        .send({ username: 'student1', password: `WrongPassword_${attempt}` });

      responses.push({
        attempt,
        status: res.status,
        body: res.body,
        rateLimitHeader: res.headers['ratelimit-remaining'] || res.headers['retry-after'],
      });

      if (res.status === 429) {
        rateLimitTriggeredRes = res;
        break;
      }
    }

    expect(rateLimitTriggeredRes).not.toBeNull();
    expect(rateLimitTriggeredRes.status).toBe(429);
    expect(rateLimitTriggeredRes.body.statusCode).toBe(429);
    expect(rateLimitTriggeredRes.body.error).toMatch(/too many login attempts/i);

    logEvidence(5, 'Brute-force protection test (triggers 429 Too Many Requests)', {
      attemptsHistory: responses,
      finalBlockedResponse: {
        status: rateLimitTriggeredRes.status,
        headers: rateLimitTriggeredRes.headers,
        body: rateLimitTriggeredRes.body,
      },
    });
  });

  /**
   * Task 6: Trusted-proxy IP handling (verifies safe client IP extraction).
   */
  test('Task 6: Trusted-proxy IP handling (verifies safe client IP extraction)', async () => {
    // 1. Single proxy hop: client IP is extracted from X-Forwarded-For
    const singleProxyIp = '203.0.113.195';
    const singleProxyRes = await request(app)
      .get('/api/auth/client-ip')
      .set('X-Forwarded-For', singleProxyIp);

    expect(singleProxyRes.status).toBe(200);
    expect(singleProxyRes.body.ip).toBe(singleProxyIp);
    expect(singleProxyRes.body.trustProxy).toBe(1);

    // 2. Chained proxy hops with trust proxy: 1:
    // Express trusts exactly 1 proxy hop upstream from the connection socket.
    // In 'clientIp, untrustedHeader', with 1 hop trusted from socket, Express safely
    // takes the verified hop (198.51.100.77 when single hop, or rightmost trusted hop 10.0.0.1).
    const chainedIps = '198.51.100.77, 10.0.0.1';
    const chainedRes = await request(app)
      .get('/api/auth/client-ip')
      .set('X-Forwarded-For', chainedIps);

    expect(chainedRes.status).toBe(200);
    expect(chainedRes.body.ip).toBe('10.0.0.1');
    expect(chainedRes.body.trustProxy).toBe(1);

    logEvidence(6, 'Trusted-proxy IP handling (verifies safe client IP extraction)', {
      singleProxyHop: {
        status: singleProxyRes.status,
        headers: singleProxyRes.headers,
        body: singleProxyRes.body,
      },
      chainedProxyHop: {
        status: chainedRes.status,
        headers: chainedRes.headers,
        body: chainedRes.body,
      },
    });
  });

  /**
   * Task 7: Session expiry & refresh behavior test.
   */
  test('Task 7: Session expiry & refresh behavior test', async () => {
    // 1. Login user
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.7.10')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const initialRefreshToken = loginRes.body.refreshToken;
    const initialAccessToken = loginRes.body.accessToken;
    expect(initialRefreshToken).toBeDefined();

    // 2. Perform legitimate refresh token rotation
    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${initialRefreshToken}`]);

    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body.accessToken).toBeDefined();
    expect(refreshRes.body.refreshToken).toBeDefined();
    expect(refreshRes.body.refreshToken).not.toBe(initialRefreshToken);

    const rotatedAccessToken = refreshRes.body.accessToken;

    // Verify newly rotated access token is accepted
    const dashRes = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${rotatedAccessToken}`);
    expect(dashRes.status).toBe(200);

    // 3. Test expired refresh token rejection
    const expiredRefreshToken = generateRefreshToken(
      { sub: 'student-001', familyId: 'fam-expired', tokenId: 'tok-expired' },
      '-10s'
    );

    const expiredRefreshRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${expiredRefreshToken}`]);

    expect(expiredRefreshRes.status).toBe(401);
    expect(expiredRefreshRes.body.error).toMatch(/expired/i);

    logEvidence(7, 'Session expiry & refresh behavior test', {
      initialLogin: {
        status: loginRes.status,
        body: { ...loginRes.body, accessToken: '[REDACTED]', refreshToken: '[REDACTED]' },
      },
      tokenRotationSuccess: {
        status: refreshRes.status,
        headers: refreshRes.headers,
        body: { message: refreshRes.body.message },
      },
      expiredRefreshResponse: {
        status: expiredRefreshRes.status,
        headers: expiredRefreshRes.headers,
        body: expiredRefreshRes.body,
      },
    });
  });

  /**
   * Task 8: Student logout revocation test (post-logout request returns 401).
   */
  test('Task 8: Student logout revocation test (post-logout request returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.8.10')
      .send({ studentId: 'STUDENT-001', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const { accessToken, refreshToken } = loginRes.body;

    // Access before logout
    const beforeLogoutRes = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(beforeLogoutRes.status).toBe(200);

    // Perform logout
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(logoutRes.status).toBe(200);
    expect(logoutRes.body.message).toBe('Logged out successfully');

    // Access after logout -> must return 401
    const afterLogoutRes = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(afterLogoutRes.status).toBe(401);
    expect(afterLogoutRes.body.error).toBe('Token has been revoked');

    // Refresh after logout -> must return 401
    const refreshAfterLogout = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(refreshAfterLogout.status).toBe(401);

    logEvidence(8, 'Student logout revocation test (post-logout request returns 401)', {
      beforeLogoutStatus: beforeLogoutRes.status,
      logoutResponse: {
        status: logoutRes.status,
        headers: logoutRes.headers,
        body: logoutRes.body,
      },
      postLogoutDashboardResponse: {
        status: afterLogoutRes.status,
        headers: afterLogoutRes.headers,
        body: afterLogoutRes.body,
      },
      postLogoutRefreshResponse: {
        status: refreshAfterLogout.status,
        body: refreshAfterLogout.body,
      },
    });
  });

  /**
   * Task 9: Master logout revocation test (post-logout request returns 401).
   */
  test('Task 9: Master logout revocation test (post-logout request returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.9.10')
      .send({ masterId: 'MASTER-001', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const { accessToken, refreshToken } = loginRes.body;

    // Access before logout
    const beforeLogoutRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(beforeLogoutRes.status).toBe(200);

    // Perform logout
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(logoutRes.status).toBe(200);

    // Access after logout -> must return 401
    const afterLogoutRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(afterLogoutRes.status).toBe(401);
    expect(afterLogoutRes.body.error).toBe('Token has been revoked');

    // Refresh after logout -> must return 401
    const refreshAfterLogout = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(refreshAfterLogout.status).toBe(401);

    // Admin setup token after logout -> must return 401
    const adminSetupAfterLogout = await request(app)
      .post('/api/auth/admin-setup-token')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(adminSetupAfterLogout.status).toBe(401);
    expect(adminSetupAfterLogout.body.error).toBe('Token has been revoked');

    logEvidence(9, 'Master logout revocation test (post-logout request returns 401)', {
      beforeLogoutStatus: beforeLogoutRes.status,
      logoutResponse: {
        status: logoutRes.status,
        headers: logoutRes.headers,
        body: logoutRes.body,
      },
      postLogoutDashboardResponse: {
        status: afterLogoutRes.status,
        headers: afterLogoutRes.headers,
        body: afterLogoutRes.body,
      },
      postLogoutRefreshResponse: {
        status: refreshAfterLogout.status,
        body: refreshAfterLogout.body,
      },
      postLogoutAdminSetupResponse: {
        status: adminSetupAfterLogout.status,
        body: adminSetupAfterLogout.body,
      },
    });
  });

  /**
   * Task 10: Instructor logout revocation test (post-logout request returns 401).
   */
  test('Task 10: Instructor logout revocation test (post-logout request returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.10.10')
      .send({ instructorId: 'INSTRUCTOR-001', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const { accessToken, refreshToken } = loginRes.body;

    // Access before logout
    const beforeLogoutRes = await request(app)
      .get('/api/instructor/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(beforeLogoutRes.status).toBe(200);

    // Perform logout
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(logoutRes.status).toBe(200);

    // Access after logout -> must return 401
    const afterLogoutRes = await request(app)
      .get('/api/instructor/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(afterLogoutRes.status).toBe(401);
    expect(afterLogoutRes.body.error).toBe('Token has been revoked');

    // Refresh after logout -> must return 401
    const refreshAfterLogout = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(refreshAfterLogout.status).toBe(401);

    logEvidence(10, 'Instructor logout revocation test (post-logout request returns 401)', {
      beforeLogoutStatus: beforeLogoutRes.status,
      logoutResponse: {
        status: logoutRes.status,
        headers: logoutRes.headers,
        body: logoutRes.body,
      },
      postLogoutDashboardResponse: {
        status: afterLogoutRes.status,
        headers: afterLogoutRes.headers,
        body: afterLogoutRes.body,
      },
      postLogoutRefreshResponse: {
        status: refreshAfterLogout.status,
        body: refreshAfterLogout.body,
      },
    });
  });

  /**
   * Task 11: Cookie security verification (checks HttpOnly, Secure, SameSite, and Path response attributes across /login, /refresh, and /logout).
   */
  test('Task 11: Cookie security verification (checks HttpOnly, Secure, SameSite, and Path response attributes)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.11.10')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const setCookieHeaders = loginRes.headers['set-cookie'];
    expect(setCookieHeaders).toBeDefined();

    const cookieString = Array.isArray(setCookieHeaders) ? setCookieHeaders.join('; ') : String(setCookieHeaders);

    // Check all 4 critical security flags on /login
    expect(cookieString).toMatch(/HttpOnly/i);
    expect(cookieString).toMatch(/Secure/i);
    expect(cookieString).toMatch(/SameSite=Strict/i);
    expect(cookieString).toMatch(/Path=\/api\/auth/i);

    // Check cookie attributes preserved on /refresh
    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${loginRes.body.refreshToken}`]);
    expect(refreshRes.status).toBe(200);

    const refreshSetCookie = refreshRes.headers['set-cookie'];
    expect(refreshSetCookie).toBeDefined();
    const refreshCookieStr = Array.isArray(refreshSetCookie) ? refreshSetCookie.join('; ') : String(refreshSetCookie);
    expect(refreshCookieStr).toMatch(/HttpOnly/i);
    expect(refreshCookieStr).toMatch(/Secure/i);
    expect(refreshCookieStr).toMatch(/SameSite=Strict/i);
    expect(refreshCookieStr).toMatch(/Path=\/api\/auth/i);

    // Check cookie clearing on /logout
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${refreshRes.body.accessToken}`)
      .set('Cookie', [`refreshToken=${refreshRes.body.refreshToken}`]);
    expect(logoutRes.status).toBe(200);

    const logoutSetCookie = logoutRes.headers['set-cookie'];
    expect(logoutSetCookie).toBeDefined();
    const logoutCookieArr = Array.isArray(logoutSetCookie) ? logoutSetCookie : [String(logoutSetCookie)];
    const authPathClear = logoutCookieArr.find((c) => /Path=\/api\/auth/i.test(c));
    expect(authPathClear).toBeDefined();
    expect(authPathClear).toMatch(/refreshToken=;/i);
    expect(authPathClear).toMatch(/Expires=Thu, 01 Jan 1970/i);
    expect(authPathClear).toMatch(/HttpOnly/i);
    expect(authPathClear).toMatch(/Secure/i);
    expect(authPathClear).toMatch(/SameSite=Strict/i);

    logEvidence(11, 'Cookie security verification (checks HttpOnly, Secure, SameSite, and Path response attributes)', {
      loginSetCookieRedacted: setCookieHeaders,
      loginParsedFlags: {
        hasHttpOnly: /HttpOnly/i.test(cookieString),
        hasSecure: /Secure/i.test(cookieString),
        hasSameSiteStrict: /SameSite=Strict/i.test(cookieString),
        hasRestrictedPath: /Path=\/api\/auth/i.test(cookieString),
      },
      refreshSetCookieRedacted: refreshSetCookie,
      refreshParsedFlags: {
        hasHttpOnly: /HttpOnly/i.test(refreshCookieStr),
        hasSecure: /Secure/i.test(refreshCookieStr),
        hasSameSiteStrict: /SameSite=Strict/i.test(refreshCookieStr),
        hasRestrictedPath: /Path=\/api\/auth/i.test(refreshCookieStr),
      },
      logoutClearCookieHeaders: logoutSetCookie,
    });
  });

  /**
   * Task 12: Persistent login & replay rejection test (reusing old refresh token revokes token family).
   */
  test('Task 12: Persistent login & replay rejection test (reusing old refresh token revokes token family)', async () => {
    // 1. Initial Login
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.0.12.10')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const token1 = loginRes.body.refreshToken;

    // 2. Legitimate Rotation 1: token1 -> token2
    const rotateRes1 = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${token1}`]);
    expect(rotateRes1.status).toBe(200);
    const token2 = rotateRes1.body.refreshToken;
    const access2 = rotateRes1.body.accessToken;

    // 3. Legitimate Rotation 2: token2 -> token3
    const rotateRes2 = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${token2}`]);
    expect(rotateRes2.status).toBe(200);
    const token3 = rotateRes2.body.refreshToken;
    const access3 = rotateRes2.body.accessToken;

    // Verify access3 works
    const validAccessRes = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${access3}`);
    expect(validAccessRes.status).toBe(200);

    // 4. MALICIOUS REPLAY ATTACK: Replay used token1
    const replayRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${token1}`]);

    expect(replayRes.status).toBe(401);
    expect(replayRes.body.code).toBe('REPLAY_ATTACK_DETECTED');
    expect(replayRes.body.error).toMatch(/Replay attack detected/i);

    // 5. Verify the entire token family is now invalidated:
    // Even the latest active refresh token (token3) must be rejected
    const rotateAfterReplayRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${token3}`]);
    expect(rotateAfterReplayRes.status).toBe(401);
    expect(rotateAfterReplayRes.body.error).toMatch(/revoked/i);

    // Access token for that family must also be rejected
    const accessAfterReplayRes = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${access3}`);
    expect(accessAfterReplayRes.status).toBe(401);
    expect(accessAfterReplayRes.body.error).toBe('Token has been revoked');

    logEvidence(12, 'Persistent login & replay rejection test (reusing old refresh token revokes token family)', {
      replayAttackAttempt: {
        status: replayRes.status,
        headers: replayRes.headers,
        body: replayRes.body,
      },
      postReplayToken3RotationAttempt: {
        status: rotateAfterReplayRes.status,
        headers: rotateAfterReplayRes.headers,
        body: rotateAfterReplayRes.body,
      },
      postReplayAccessTokenAttempt: {
        status: accessAfterReplayRes.status,
        headers: accessAfterReplayRes.headers,
        body: accessAfterReplayRes.body,
      },
    });
  });

  /**
   * Task 13: Argon2id password hashing & weak-password protection (R3 helper-level verification).
   * Note: Tested at the helper level because src/ is unmodified per approved Option 2.
   */
  test('Task 13: Argon2id password hashing & weak-password protection (R3)', async () => {
    const syntheticStrong = 'Kka!Synthetic9Test#2026';
    const syntheticWrong = 'Kka!Wrong9Test#2026';

    // 1. Verify Argon2id hash format and OWASP parameters (m=65536, t=3, p=1)
    const hash = await hashPassword(syntheticStrong);
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);

    const validMatch = await verifyPassword(hash, syntheticStrong);
    const wrongMatch = await verifyPassword(hash, syntheticWrong);
    const malformedMatch = await verifyPassword('not-a-valid-argon2-hash', syntheticStrong);
    expect(validMatch).toBe(true);
    expect(wrongMatch).toBe(false);
    expect(malformedMatch).toBe(false);

    // 2. Verify weak-password policy enforcement via validatePasswordStrength
    const weakCases = [
      { label: 'length < 8', candidate: 'Ab1!xyz' },
      { label: 'common weak (password123)', candidate: 'password123' },
      { label: 'common weak (karate123)', candidate: 'karate123' },
      { label: 'common weak (12345678)', candidate: '12345678' },
      { label: 'missing uppercase', candidate: 'weakpass1!' },
      { label: 'missing lowercase', candidate: 'WEAKPASS1!' },
      { label: 'missing digit', candidate: 'WeakPass!!' },
      { label: 'missing special character', candidate: 'WeakPass12' },
    ];

    const weakResults = weakCases.map((tc) => {
      const res = validatePasswordStrength(tc.candidate);
      expect(res.valid).toBe(false);
      expect(res.reason).toBeDefined();
      return { case: tc.label, valid: res.valid, reason: res.reason };
    });

    const strongResult = validatePasswordStrength(syntheticStrong);
    expect(strongResult.valid).toBe(true);

    const paramPrefix = hash.split('$').slice(0, 4).join('$');
    logEvidence(13, 'Argon2id password hashing & weak-password protection (R3)', {
      scopeNote: 'validatePasswordStrength verified at helper level (src/ unmodified per Option 2; no route invokes it)',
      argon2id: {
        parameterPrefix: paramPrefix,
        matchesStrongPassword: validMatch,
        rejectsWrongPassword: !wrongMatch,
        rejectsMalformedHash: !malformedMatch,
      },
      weakPasswordRejections: weakResults,
      strongPasswordAccepted: strongResult,
    });
  });

  /**
   * Task 14: JWT 8-hour access token & 15-minute admin setup token lifetimes and RBAC (R3).
   */
  test('Task 14: JWT 8-hour access & 15-minute admin setup token lifetimes (R3)', async () => {
    // 1. Master login -> verify 8-hour (28800s) access token lifetime
    const masterLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.1')
      .send({ masterId: 'MASTER-001', password: 'StrongP@ssw0rd!' });
    expect(masterLogin.status).toBe(200);

    const masterDecoded = jwt.decode(masterLogin.body.accessToken) as jwt.JwtPayload;
    expect(masterDecoded).not.toBeNull();
    expect(masterDecoded.type).toBe('access');
    expect(masterDecoded.role).toBe(Role.MASTER);
    expect(masterDecoded.exp! - masterDecoded.iat!).toBe(28800);

    // 2. Master requests admin setup token -> 200 & 15-minute (900s) lifetime
    const masterAdminRes = await request(app)
      .post('/api/auth/admin-setup-token')
      .set('Authorization', `Bearer ${masterLogin.body.accessToken}`);
    expect(masterAdminRes.status).toBe(200);
    expect(masterAdminRes.body.expiresIn).toBe('15m');
    expect(masterAdminRes.body.adminSetupToken).toBeDefined();

    const masterAdminDecoded = jwt.decode(masterAdminRes.body.adminSetupToken) as jwt.JwtPayload;
    expect(masterAdminDecoded.type).toBe('admin_setup');
    expect(masterAdminDecoded.role).toBe(Role.MASTER);
    expect(masterAdminDecoded.exp! - masterAdminDecoded.iat!).toBe(900);

    const verifiedMasterAdmin = verifyAdminSetupToken(masterAdminRes.body.adminSetupToken);
    expect(verifiedMasterAdmin.valid).toBe(true);
    expect(verifiedMasterAdmin.expired).toBe(false);
    expect(verifiedMasterAdmin.payload?.role).toBe(Role.MASTER);

    // 3. President alias requests admin setup token -> 200 & 15-minute (900s) lifetime
    const presidentLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.2')
      .send({ presidentId: 'PRESIDENT-001', password: 'StrongP@ssw0rd!' });
    expect(presidentLogin.status).toBe(200);

    const presidentAdminRes = await request(app)
      .post('/api/auth/admin-setup-token')
      .set('Authorization', `Bearer ${presidentLogin.body.accessToken}`);
    expect(presidentAdminRes.status).toBe(200);
    expect(presidentAdminRes.body.expiresIn).toBe('15m');

    const presidentAdminDecoded = jwt.decode(presidentAdminRes.body.adminSetupToken) as jwt.JwtPayload;
    expect(presidentAdminDecoded.type).toBe('admin_setup');
    expect(presidentAdminDecoded.role).toBe(Role.MASTER);
    expect(presidentAdminDecoded.exp! - presidentAdminDecoded.iat!).toBe(900);

    const verifiedPresidentAdmin = verifyAdminSetupToken(presidentAdminRes.body.adminSetupToken);
    expect(verifiedPresidentAdmin.valid).toBe(true);

    // 4. Student, Instructor, and unauthenticated requests to /admin-setup-token -> 401
    const studentLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.3')
      .send({ studentId: 'STUDENT-001', password: 'StrongP@ssw0rd!' });
    const studentAdminRes = await request(app)
      .post('/api/auth/admin-setup-token')
      .set('Authorization', `Bearer ${studentLogin.body.accessToken}`);
    expect(studentAdminRes.status).toBe(401);

    const instructorLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.4')
      .send({ instructorId: 'INSTRUCTOR-001', password: 'StrongP@ssw0rd!' });
    const instructorAdminRes = await request(app)
      .post('/api/auth/admin-setup-token')
      .set('Authorization', `Bearer ${instructorLogin.body.accessToken}`);
    expect(instructorAdminRes.status).toBe(401);

    const unauthAdminRes = await request(app).post('/api/auth/admin-setup-token');
    expect(unauthAdminRes.status).toBe(401);

    // 5. verifyAdminSetupToken rejects expired, tampered, and cross-type tokens
    const expiredAdminToken = generateAdminSetupToken('master-001', Role.MASTER, '-5s');
    const expiredCheck = verifyAdminSetupToken(expiredAdminToken);
    expect(expiredCheck.valid).toBe(false);
    expect(expiredCheck.expired).toBe(true);

    const adminParts = masterAdminRes.body.adminSetupToken.split('.');
    const tamperedAdminToken = `${adminParts[0]}.${adminParts[1]}.CORRUPTED_SIG`;
    const tamperedCheck = verifyAdminSetupToken(tamperedAdminToken);
    expect(tamperedCheck.valid).toBe(false);
    expect(tamperedCheck.expired).toBe(false);

    const crossTypeCheck = verifyAdminSetupToken(masterLogin.body.accessToken);
    expect(crossTypeCheck.valid).toBe(false);

    logEvidence(14, 'JWT 8-hour access & 15-minute admin setup token lifetimes (R3)', {
      accessTokenClaims: {
        type: masterDecoded.type,
        role: masterDecoded.role,
        lifetimeSeconds: masterDecoded.exp! - masterDecoded.iat!,
        expectedSeconds: 28800,
      },
      masterAdminSetup: {
        status: masterAdminRes.status,
        expiresIn: masterAdminRes.body.expiresIn,
        type: masterAdminDecoded.type,
        role: masterAdminDecoded.role,
        lifetimeSeconds: masterAdminDecoded.exp! - masterAdminDecoded.iat!,
        verifyValid: verifiedMasterAdmin.valid,
      },
      presidentAdminSetup: {
        status: presidentAdminRes.status,
        expiresIn: presidentAdminRes.body.expiresIn,
        type: presidentAdminDecoded.type,
        role: presidentAdminDecoded.role,
        lifetimeSeconds: presidentAdminDecoded.exp! - presidentAdminDecoded.iat!,
        verifyValid: verifiedPresidentAdmin.valid,
      },
      adminSetupNegativeRbac: {
        studentStatus: studentAdminRes.status,
        instructorStatus: instructorAdminRes.status,
        unauthenticatedStatus: unauthAdminRes.status,
      },
      verifyAdminSetupNegative: {
        expired: { valid: expiredCheck.valid, expired: expiredCheck.expired },
        tampered: { valid: tamperedCheck.valid, expired: tamperedCheck.expired },
        crossTypeAccessToken: { valid: crossTypeCheck.valid, error: crossTypeCheck.error },
      },
    });
  });

  /**
   * Task 15: Full Role & Cross-Token-Type Negative JWT Matrix (R2, R3).
   */
  test('Task 15: Full Role & Cross-Token-Type Negative JWT Matrix (R2, R3)', async () => {
    const studentLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.5')
      .send({ studentId: 'STUDENT-001', password: 'StrongP@ssw0rd!' });
    const instructorLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.6')
      .send({ instructorId: 'INSTRUCTOR-001', password: 'StrongP@ssw0rd!' });
    const masterLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.7')
      .send({ masterId: 'MASTER-001', password: 'StrongP@ssw0rd!' });
    const presidentIdLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.8')
      .send({ presidentId: 'PRESIDENT-001', password: 'StrongP@ssw0rd!' });
    const presidentRoleLogin = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.9')
      .send({ username: 'president1', role: 'PRESIDENT', password: 'StrongP@ssw0rd!' });

    expect(studentLogin.status).toBe(200);
    expect(instructorLogin.status).toBe(200);
    expect(masterLogin.status).toBe(200);
    expect(presidentIdLogin.status).toBe(200);
    expect(presidentRoleLogin.status).toBe(200);
    expect(presidentRoleLogin.body.user.role).toBe(Role.MASTER);

    const checkMatrix = async (token: string) => {
      const s = await request(app).get('/api/student/dashboard').set('Authorization', `Bearer ${token}`);
      const i = await request(app).get('/api/instructor/dashboard').set('Authorization', `Bearer ${token}`);
      const m = await request(app).get('/api/master/dashboard').set('Authorization', `Bearer ${token}`);
      return { studentDash: s.status, instructorDash: i.status, masterDash: m.status };
    };

    const studentMatrix = await checkMatrix(studentLogin.body.accessToken);
    expect(studentMatrix).toEqual({ studentDash: 200, instructorDash: 401, masterDash: 401 });

    const instructorMatrix = await checkMatrix(instructorLogin.body.accessToken);
    expect(instructorMatrix).toEqual({ studentDash: 401, instructorDash: 200, masterDash: 401 });

    const masterMatrix = await checkMatrix(masterLogin.body.accessToken);
    expect(masterMatrix).toEqual({ studentDash: 401, instructorDash: 401, masterDash: 200 });

    const presidentIdMatrix = await checkMatrix(presidentIdLogin.body.accessToken);
    expect(presidentIdMatrix).toEqual({ studentDash: 401, instructorDash: 401, masterDash: 200 });

    const presidentRoleMatrix = await checkMatrix(presidentRoleLogin.body.accessToken);
    expect(presidentRoleMatrix).toEqual({ studentDash: 401, instructorDash: 401, masterDash: 200 });

    // Cross-token-type rejection: refreshToken and adminSetupToken passed as Bearer access tokens
    const adminSetupRes = await request(app)
      .post('/api/auth/admin-setup-token')
      .set('Authorization', `Bearer ${masterLogin.body.accessToken}`);
    expect(adminSetupRes.status).toBe(200);

    const refreshAsBearerRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${masterLogin.body.refreshToken}`);
    expect(refreshAsBearerRes.status).toBe(401);

    const adminAsBearerRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${adminSetupRes.body.adminSetupToken}`);
    expect(adminAsBearerRes.status).toBe(401);

    const missingAuthRes = await request(app).get('/api/master/dashboard');
    expect(missingAuthRes.status).toBe(401);

    logEvidence(15, 'Full Role & Cross-Token-Type Negative JWT Matrix (R2, R3)', {
      roleMatrix: {
        STUDENT: studentMatrix,
        INSTRUCTOR: instructorMatrix,
        MASTER: masterMatrix,
        PRESIDENT_BY_ID: presidentIdMatrix,
        PRESIDENT_BY_ROLE_PARAM: presidentRoleMatrix,
      },
      crossTokenTypeRejection: {
        refreshTokenAsBearerStatus: refreshAsBearerRes.status,
        adminSetupTokenAsBearerStatus: adminAsBearerRes.status,
        missingBearerStatus: missingAuthRes.status,
      },
    });
  });

  /**
   * Task 16: President alias logout revocation test (R2, R4).
   */
  test('Task 16: President alias logout revocation test (R2, R4)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '10.50.0.10')
      .send({ presidentId: 'PRESIDENT-001', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);
    expect(loginRes.body.user.role).toBe(Role.MASTER);

    const { accessToken, refreshToken } = loginRes.body;

    const beforeLogoutRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(beforeLogoutRes.status).toBe(200);

    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(logoutRes.status).toBe(200);

    const afterLogoutDashRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(afterLogoutDashRes.status).toBe(401);
    expect(afterLogoutDashRes.body.error).toBe('Token has been revoked');

    const afterLogoutRefreshRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(afterLogoutRefreshRes.status).toBe(401);

    const afterLogoutAdminSetupRes = await request(app)
      .post('/api/auth/admin-setup-token')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(afterLogoutAdminSetupRes.status).toBe(401);

    logEvidence(16, 'President alias logout revocation test (R2, R4)', {
      beforeLogoutStatus: beforeLogoutRes.status,
      logoutStatus: logoutRes.status,
      postLogoutMasterDashStatus: afterLogoutDashRes.status,
      postLogoutRefreshStatus: afterLogoutRefreshRes.status,
      postLogoutAdminSetupStatus: afterLogoutAdminSetupRes.status,
    });
  });
});
