import { Inject, Injectable, Optional } from '@nestjs/common';
import * as crypto from 'crypto';

export type UserRole = 'admin' | 'moderator' | 'user' | 'guest';

export interface AuthenticatedUser {
  id: number;
  username: string;
  role: UserRole;
}

export interface AuthResult {
  ok: boolean;
  user?: AuthenticatedUser;
  token?: string;
  reason?: 'invalid' | 'locked';
}

interface StoredUser extends AuthenticatedUser {
  credentialHash: string;
  credentialSalt: string;
}

interface AuthPolicy {
  maxFailedAttempts: number;
  lockoutMs: number;
  tokenTtlSeconds: number;
  tokenSecret: Buffer;
  users: StoredUser[];
}

interface FailureState {
  count: number;
  lockedUntil: number;
}

const DEFAULT_USER_PROFILES: AuthenticatedUser[] = [
  { id: 1, username: 'admin', role: 'admin' },
  { id: 2, username: 'user', role: 'user' },
  { id: 3, username: 'guest', role: 'guest' },
];

@Injectable()
export class AuthService {
  private readonly policy: AuthPolicy;
  private readonly failures = new Map<string, FailureState>();

  constructor(@Optional() @Inject('AUTH_POLICY') policy?: Partial<AuthPolicy>) {
    this.policy = {
      maxFailedAttempts: parseInt(process.env.AUTH_MAX_FAILED_ATTEMPTS || '5', 10),
      lockoutMs: parseInt(process.env.AUTH_LOCKOUT_MS || '300000', 10),
      tokenTtlSeconds: parseInt(process.env.AUTH_TOKEN_TTL_SECONDS || '900', 10),
      tokenSecret: process.env.AUTH_TOKEN_SECRET
        ? Buffer.from(process.env.AUTH_TOKEN_SECRET, 'utf8')
        : crypto.randomBytes(32),
      users: this.buildDefaultUsers(),
      ...policy,
    };
  }

  async authenticate(
    username: string,
    submittedCredential: string,
    sourceIp = 'unknown',
  ): Promise<AuthResult> {
    const normalizedUsername = this.normalizeUsername(username);
    const failureKey = `${normalizedUsername}:${sourceIp}`;

    if (this.isLocked(failureKey)) {
      return { ok: false, reason: 'locked' };
    }

    const user = this.policy.users.find((item) => item.username === normalizedUsername);
    const verified = user
      ? this.verifyCredential(submittedCredential, user.credentialSalt, user.credentialHash)
      : false;

    if (!user || !verified) {
      this.recordFailure(failureKey);
      return { ok: false, reason: 'invalid' };
    }

    this.failures.delete(failureKey);
    const publicUser = this.toPublicUser(user);
    return {
      ok: true,
      user: publicUser,
      token: this.issueAccessToken(publicUser),
    };
  }

  async validateUser(username: string, submittedCredential: string): Promise<AuthenticatedUser | null> {
    const result = await this.authenticate(username, submittedCredential);
    return result.ok && result.user ? result.user : null;
  }

  verifyAccessToken(token: string): AuthenticatedUser | null {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [encodedHeader, encodedPayload, signature] = parts;
    const expectedSignature = this.sign(`${encodedHeader}.${encodedPayload}`);
    if (!this.timingSafeCompare(signature, expectedSignature)) {
      return null;
    }

    try {
      const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
      if (!payload.exp || Date.now() >= payload.exp * 1000) {
        return null;
      }

      const user = this.policy.users.find((item) => item.id === payload.sub);
      if (!user || user.username !== payload.username || user.role !== payload.role) {
        return null;
      }

      return this.toPublicUser(user);
    } catch {
      return null;
    }
  }

  private buildDefaultUsers(): StoredUser[] {
    return DEFAULT_USER_PROFILES.map((profile) => {
      const credential = process.env[`LAB_${profile.username.toUpperCase()}_LOGIN_VALUE`] || profile.username;
      const credentialSalt = `secure-learn:${profile.username}`;
      return {
        ...profile,
        credentialSalt,
        credentialHash: this.hashCredential(credential, credentialSalt),
      };
    });
  }

  private normalizeUsername(username: string): string {
    return String(username || '').trim().toLowerCase();
  }

  private hashCredential(credential: string, salt: string): string {
    // PBKDF2 keeps the lab dependency-free while demonstrating slow credential verification.
    // Production services should use managed identity or a dedicated password hashing library.
    return crypto.pbkdf2Sync(String(credential), salt, 120000, 32, 'sha256').toString('base64url');
  }

  private verifyCredential(credential: string, salt: string, expectedHash: string): boolean {
    return this.timingSafeCompare(this.hashCredential(credential, salt), expectedHash);
  }

  private timingSafeCompare(left: string, right: string): boolean {
    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);
    if (leftBuffer.length !== rightBuffer.length) {
      return false;
    }
    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
  }

  private isLocked(failureKey: string): boolean {
    const state = this.failures.get(failureKey);
    if (!state) {
      return false;
    }
    if (state.lockedUntil > 0 && Date.now() >= state.lockedUntil) {
      this.failures.delete(failureKey);
      return false;
    }
    return state.count >= this.policy.maxFailedAttempts;
  }

  private recordFailure(failureKey: string): void {
    const state = this.failures.get(failureKey) || { count: 0, lockedUntil: 0 };
    state.count += 1;
    if (state.count >= this.policy.maxFailedAttempts) {
      state.lockedUntil = Date.now() + this.policy.lockoutMs;
    }
    this.failures.set(failureKey, state);
  }

  private issueAccessToken(user: AuthenticatedUser): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({
        sub: user.id,
        username: user.username,
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + this.policy.tokenTtlSeconds,
      }),
    ).toString('base64url');
    const unsigned = `${header}.${payload}`;
    return `${unsigned}.${this.sign(unsigned)}`;
  }

  private sign(value: string): string {
    return crypto.createHmac('sha256', this.policy.tokenSecret).update(value).digest('base64url');
  }

  private toPublicUser(user: StoredUser): AuthenticatedUser {
    return {
      id: user.id,
      username: user.username,
      role: user.role,
    };
  }
}

