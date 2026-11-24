import request from 'supertest';
import { app } from '../src/app';
import { userRepository } from '../src/auth/users';
import { sessionStore } from '../src/auth/session';
import { resolvePresidentScope } from '../src/auth/roles';
import { Role } from '../src/auth/types';
import { generateAccessToken } from '../src/auth/jwt';
import jwt from 'jsonwebtoken';

describe('Builder Self-Verification Test Suite (Section 1 Readiness)', () => {
  beforeAll(async () => {
    await userRepository.initialize();
  });

  beforeEach(() => {
    sessionStore.clear();
  });

  test('1. Confirm President role scope resolution in code', () => {
    const resolved = resolvePresidentScope('PRESIDENT');
    expect(resolved).toBe(Role.MASTER);
  });

  test('2. Wrong-role JWT rejection (returns 401/403)', async () => {
    // Student trying to access master dashboard
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const studentToken = loginRes.body.accessToken;

    const res = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${studentToken}`);
    expect([401, 403]).toContain(res.status);
  });

  test('3. Expired JWT rejection (returns 401)', async () => {
    const expiredToken = generateAccessToken(
      { sub: 'student-001', username: 'student1', role: Role.STUDENT, sessionId: 's1', familyId: 'f1' },
      '-1s'
    );

    const res = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${expiredToken}`);
    expect(res.status).toBe(401);
  });

  test('4. Tampered JWT rejection (returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    const validToken = loginRes.body.accessToken;

    // Tamper with the token payload
    const parts = validToken.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'admin', role: 'MASTER' })).toString('base64url');
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const res = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${tamperedToken}`);
    expect(res.status).toBe(401);
  });

  test('5. Brute-force protection test (triggers 429 Too Many Requests)', async () => {
    // 5 attempts should eventually trigger rate limiting
    let rateLimited = false;
    for (let i = 0; i < 10; i++) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: 'student1', password: 'WrongPassword!' });
      if (res.status === 429) {
        rateLimited = true;
        break;
      }
    }
    expect(rateLimited).toBe(true);
  });

  test('6. Trusted-proxy IP handling (verifies safe client IP extraction)', async () => {
    const res = await request(app)
      .get('/api/auth/client-ip')
      .set('X-Forwarded-For', '203.0.113.195');
    expect(res.status).toBe(200);
    expect(res.body.ip).toBe('203.0.113.195');
  });

  test('7. Session expiry & refresh behavior test', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '198.51.100.10')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const refreshToken = loginRes.body.refreshToken;
    expect(refreshToken).toBeDefined();

    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body.accessToken).toBeDefined();
    expect(refreshRes.body.refreshToken).toBeDefined();
    expect(refreshRes.body.refreshToken).not.toBe(refreshToken);
  });

  test('8. Student logout revocation test (post-logout request returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '198.51.100.20')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    const { accessToken, refreshToken } = loginRes.body;

    // Access dashboard before logout
    const dashBefore = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(dashBefore.status).toBe(200);

    // Logout
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(logoutRes.status).toBe(200);

    // Access dashboard after logout -> 401
    const dashAfter = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(dashAfter.status).toBe(401);
  });

  test('9. Master logout revocation test (post-logout request returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '198.51.100.30')
      .send({ masterId: 'MASTER-001', password: 'StrongP@ssw0rd!' });
    const { accessToken, refreshToken } = loginRes.body;

    const dashBefore = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(dashBefore.status).toBe(200);

    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(logoutRes.status).toBe(200);

    const dashAfter = await request(app)
      .get('/api/master/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(dashAfter.status).toBe(401);
  });

  test('10. Instructor logout revocation test (post-logout request returns 401)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '198.51.100.40')
      .send({ instructorId: 'INSTRUCTOR-001', password: 'StrongP@ssw0rd!' });
    const { accessToken, refreshToken } = loginRes.body;

    const dashBefore = await request(app)
      .get('/api/instructor/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(dashBefore.status).toBe(200);

    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', [`refreshToken=${refreshToken}`]);
    expect(logoutRes.status).toBe(200);

    const dashAfter = await request(app)
      .get('/api/instructor/dashboard')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(dashAfter.status).toBe(401);
  });

  test('11. Cookie security verification (checks HttpOnly, Secure, SameSite, and Path response attributes)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '198.51.100.50')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    expect(loginRes.status).toBe(200);

    const setCookieHeaders = loginRes.headers['set-cookie'];
    expect(setCookieHeaders).toBeDefined();

    const cookieStr = Array.isArray(setCookieHeaders) ? setCookieHeaders.join('; ') : setCookieHeaders;
    expect(cookieStr).toMatch(/HttpOnly/i);
    expect(cookieStr).toMatch(/Secure/i);
    expect(cookieStr).toMatch(/SameSite=Strict/i);
    expect(cookieStr).toMatch(/Path=\/api\/auth/i);
  });

  test('12. Persistent login & replay rejection test (reusing old refresh token revokes token family)', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('X-Forwarded-For', '198.51.100.60')
      .send({ username: 'student1', password: 'StrongP@ssw0rd!' });
    const token1 = loginRes.body.refreshToken;

    // First rotation (valid)
    const rotate1 = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${token1}`]);
    expect(rotate1.status).toBe(200);
    const token2 = rotate1.body.refreshToken;
    const access2 = rotate1.body.accessToken;

    // Verify token2 works
    const dashValid = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${access2}`);
    expect(dashValid.status).toBe(200);

    // REPLAY ATTACK: Re-use token1
    const replayRes = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${token1}`]);
    expect(replayRes.status).toBe(401);
    expect(replayRes.body.code).toBe('REPLAY_ATTACK_DETECTED');

    // Token family should now be revoked! Even token2 must now be rejected
    const rotate2 = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${token2}`]);
    expect(rotate2.status).toBe(401);

    // Access token for that family should also be rejected
    const dashAfterReplay = await request(app)
      .get('/api/student/dashboard')
      .set('Authorization', `Bearer ${access2}`);
    expect(dashAfterReplay.status).toBe(401);
  });
});
