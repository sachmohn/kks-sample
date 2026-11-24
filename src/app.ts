import express, { Express, Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import { authRouter } from './auth/routes';
import { academyRouter } from './academy/routes';
import { authenticateToken, requireRole } from './auth/middleware';
import { Role } from './auth/types';

export const app: Express = express();

/**
 * Trusted-proxy configuration:
 * Tells Express to trust reverse proxy headers (e.g. Nginx, Cloudflare, AWS ALB)
 * ensuring safe and accurate extraction of client IP (req.ip) from X-Forwarded-For.
 */
app.set('trust proxy', 1);

// Standard body & cookie parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static file serving for the Web Prototype Portal
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Auth endpoints (/login, /refresh, /logout, /admin-setup-token, /client-ip)
app.use('/api/auth', authRouter);

// Interactive Academy Management endpoints (/students, /classes, /stats, /promote, /attendance)
app.use('/api/academy', academyRouter);

/**
 * Protected Dashboard Endpoints
 */

// Student Dashboard (Requires STUDENT role)
app.get('/api/student/dashboard', authenticateToken, requireRole(Role.STUDENT), (req: Request, res: Response) => {
  res.status(200).json({
    message: 'Welcome to the Student Dashboard',
    role: req.user?.role,
    user: {
      id: req.user?.sub,
      username: req.user?.username,
    },
  });
});

// Instructor Dashboard (Requires INSTRUCTOR role)
app.get('/api/instructor/dashboard', authenticateToken, requireRole(Role.INSTRUCTOR), (req: Request, res: Response) => {
  res.status(200).json({
    message: 'Welcome to the Instructor Dashboard',
    role: req.user?.role,
    user: {
      id: req.user?.sub,
      username: req.user?.username,
    },
  });
});

// Master Dashboard (Requires MASTER role - accessible to Master and President scope)
app.get('/api/master/dashboard', authenticateToken, requireRole(Role.MASTER), (req: Request, res: Response) => {
  res.status(200).json({
    message: 'Welcome to the Master Dashboard',
    role: req.user?.role,
    user: {
      id: req.user?.sub,
      username: req.user?.username,
    },
  });
});

// SPA fallback handler for non-API GET requests
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.method === 'GET' && !req.path.startsWith('/api') && !req.path.startsWith('/health')) {
    const publicIndex = path.join(__dirname, '../public/index.html');
    return res.sendFile(publicIndex, (err) => {
      if (err) {
        res.status(404).send('Khan Karate Academy Portal index.html not found.');
      }
    });
  }
  next();
});

// Global Error Handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled server error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
  });
});
