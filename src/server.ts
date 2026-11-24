import { app } from './app';
import { userRepository } from './auth/users';

const PORT = process.env.PORT || 3000;

let initialized = false;
async function ensureInitialized() {
  if (!initialized) {
    await userRepository.initialize();
    initialized = true;
  }
}

async function bootstrap() {
  await ensureInitialized();

  const server = app.listen(PORT, () => {
    console.log(`🥋 Khan's Karate Academy Auth Server running on port ${PORT}`);
  });

  return server;
}

// Only bind to a port when running locally (not on Vercel or during Jest tests)
if (process.env.NODE_ENV !== 'test' && !process.env.VERCEL) {
  bootstrap().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}

// Ensure users are initialized before handling requests on Vercel
app.use(async (_req, _res, next) => {
  await ensureInitialized();
  next();
});

export default app;
export { bootstrap };
