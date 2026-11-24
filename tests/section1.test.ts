import request from 'supertest';
import { app } from '../src/app';
import { userRepository } from '../src/auth/users';
import { sessionStore } from '../src/auth/session';
import { resolvePresidentScope, isAuthorizedForRole } from '../src/auth/roles';
import { Role, PRESIDENT_SCOPE_RESOLUTION } from '../src/auth/types';
import { generateAccessToken, generateRefreshToken } from '../src/auth/jwt';

// Helper to format and display raw HTTP audit evidence in stdout
function logEvidence(taskNumber: number, taskTitle: string, data: Record<string, any>) {
  console.log(`\n======================================================================`);
  console.log(`[AUDIT EVIDENCE - TASK ${taskNumber}] ${taskTitle}`);
  console.log(`======================================================================`);
  for (const [key, val] of Object.entries(data)) {
    if (typeof val === 'object' && val !== null) {
      console.log(`--- ${key} ---`);
      console.log(JSON.stringify(val, null, 2));
    } else {
      console.log(`${key}: ${val}`);
    }
  }
  console.log(`======================================================================\n`);
}

describe('KKA Section 1 Security Audit Test Suite', () => {
  beforeAll(async () => {
    await userRepository.initialize();
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
      loginResponseBody: loginRes.body,
      masterDashboardStatus: masterDashRes.status,
      masterDashboardBody: masterDashRes.body,
    });
  });

  /**
   * Task 2: Wrong-role JWT rejection (returns 401/403).
   */
  test('Task 2: Wrong-role JWT rejection (returns 401/403)', async () => {
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
    expect([401, 403]).toContain(studentToMasterRes.status);

    // Student attempts to access Instructor dashboard
    const studentToInstructorRes = await request(app)
      .get('/api/instructor/dashboard')
      .set('Authorization', `Bearer ${studentToken}`);
    expect([401, 403]).toContain(studentToInstructorRes.status);

    // Instructor attempts to access Master dashboard
    const instructorToMasterRes = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${instructorToken}`);
    expect([401, 403]).toContain(instructorToMasterRes.status);

    logEvidence(2, 'Wrong-role JWT rejection (returns 401/403)', {
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
    });
  });

  /**
   * Task 11: Cookie security verification (checks HttpOnly, Secure, SameSite, and Path response attributes).
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

    // Check all 4 critical security flags
    expect(cookieString).toMatch(/HttpOnly/i);
    expect(cookieString).toMatch(/Secure/i);
    expect(cookieString).toMatch(/SameSite=Strict/i);
    expect(cookieString).toMatch(/Path=\/api\/auth/i);

    logEvidence(11, 'Cookie security verification (checks HttpOnly, Secure, SameSite, and Path response attributes)', {
      setCookieHeaderRaw: setCookieHeaders,
      parsedFlags: {
        hasHttpOnly: /HttpOnly/i.test(cookieString),
        hasSecure: /Secure/i.test(cookieString),
        hasSameSiteStrict: /SameSite=Strict/i.test(cookieString),
        hasRestrictedPath: /Path=\/api\/auth/i.test(cookieString),
      },
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
});
