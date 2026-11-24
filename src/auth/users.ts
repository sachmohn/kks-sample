import { User, Role, PRESIDENT_SCOPE_RESOLUTION } from './types';
import { hashPassword } from './password';

export class UserRepository {
  private users: Map<string, User> = new Map();
  private initialized: boolean = false;
  private initPromise: Promise<void> | null = null;

  public async initialize(): Promise<void> {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      const defaultPasswordHash = await hashPassword('StrongP@ssw0rd!');

      // 1. Seed Student
      this.addUser({
        id: 'student-001',
        username: 'student1',
        role: Role.STUDENT,
        passwordHash: defaultPasswordHash,
        name: 'Karate Student',
        studentId: 'STUDENT-001',
      });

      // 2. Seed Instructor
      this.addUser({
        id: 'instructor-001',
        username: 'instructor1',
        role: Role.INSTRUCTOR,
        passwordHash: defaultPasswordHash,
        name: 'Karate Instructor',
        instructorId: 'INSTRUCTOR-001',
      });

      // 3. Seed Master
      this.addUser({
        id: 'master-001',
        username: 'master1',
        role: Role.MASTER,
        passwordHash: defaultPasswordHash,
        name: 'Karate Grandmaster',
        masterId: 'MASTER-001',
      });

      // 4. Seed President (Resolves directly to Role.MASTER)
      this.addUser({
        id: 'president-001',
        username: 'president1',
        role: PRESIDENT_SCOPE_RESOLUTION,
        passwordHash: defaultPasswordHash,
        name: 'Academy President',
        presidentId: 'PRESIDENT-001',
      });

      this.initialized = true;
    })();

    return this.initPromise;
  }

  public addUser(user: User): void {
    this.users.set(user.id, user);
  }

  public getUserById(id: string): User | undefined {
    return this.users.get(id);
  }

  public findUserByIdentifier(identifier: string): User | undefined {
    if (!identifier) return undefined;
    const lower = identifier.trim().toLowerCase();

    for (const user of this.users.values()) {
      if (
        user.id.toLowerCase() === lower ||
        user.username.toLowerCase() === lower ||
        (user.studentId && user.studentId.toLowerCase() === lower) ||
        (user.instructorId && user.instructorId.toLowerCase() === lower) ||
        (user.masterId && user.masterId.toLowerCase() === lower) ||
        (user.presidentId && user.presidentId.toLowerCase() === lower)
      ) {
        return user;
      }
    }
    return undefined;
  }

  public getAllUsers(): User[] {
    return Array.from(this.users.values());
  }

  public clear(): void {
    this.users.clear();
    this.initialized = false;
    this.initPromise = null;
  }
}

export const userRepository = new UserRepository();
