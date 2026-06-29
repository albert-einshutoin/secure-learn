import { Injectable } from '@nestjs/common';

// Hardcoded users for demonstration
const USERS = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user', password: 'user123', role: 'user' },
  { id: 3, username: 'guest', password: 'guest', role: 'guest' },
];

@Injectable()
export class AuthService {
  async validateUser(username: string, password: string): Promise<any> {
    // Intentionally simple authentication for learning purposes
    const user = USERS.find(
      (u) => u.username === username && u.password === password,
    );

    if (user) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }
}

