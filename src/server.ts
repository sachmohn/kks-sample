import { app } from './app';
import { userRepository } from './auth/users';

const PORT = process.env.PORT || 3000;

async function bootstrap() {
  await userRepository.initialize();

  const server = app.listen(PORT, () => {
    console.log(`🥋 Khan's Karate Academy Auth Server running on port ${PORT}`);
  });

  return server;
}

if (process.env.NODE_ENV !== 'test') {
  bootstrap().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}

export { bootstrap };
