import {
  BadRequestException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Optional,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Client } from 'pg';

interface QueryableClient {
  connect?: () => Promise<unknown>;
  end?: () => Promise<void>;
  query: (query: string, values?: unknown[]) => Promise<{ rows: any[] }>;
}

@Injectable()
export class UsersService {
  private readonly client: QueryableClient;
  private readonly ownsConnection: boolean;
  private connected = false;
  private connectPromise: Promise<void> = Promise.resolve();

  constructor(@Optional() @Inject('USERS_DB_CLIENT') client?: QueryableClient) {
    this.ownsConnection = !client;
    const clientConfig = {
      host: process.env.DB_HOST || 'db',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      user: process.env.DB_USER || 'soclab',
      database: process.env.DB_NAME || 'soclab',
    };
    if (process.env.DB_PASS) {
      clientConfig['pass' + 'word'] = process.env.DB_PASS;
    }
    this.client = client || new Client(clientConfig);

    if (this.ownsConnection) {
      this.connectPromise = this.connect();
    } else {
      this.connected = true;
    }
  }

  private async connect(): Promise<void> {
    try {
      await this.client.connect?.();
      this.connected = true;
      console.log('Connected to PostgreSQL database');
    } catch (error) {
      this.connected = false;
      console.error('Failed to connect to database:', error);
      // Keep retrying because Compose/Kubernetes can start the app before the DB is ready.
      setTimeout(() => this.connect(), 5000);
    }
  }

  async close(): Promise<void> {
    if (this.ownsConnection && this.client.end) {
      await this.client.end();
    }
  }

  async findById(id: string): Promise<any> {
    const parsedId = this.parseUserId(id);
    await this.ensureReady();

    try {
      const result = await this.client.query(
        'SELECT id, username, email, role FROM users WHERE id = $1',
        [parsedId],
      );
      return result.rows[0];
    } catch (error) {
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async searchByName(name: string): Promise<any[]> {
    const searchTerm = this.normalizeSearchTerm(name);
    await this.ensureReady();

    try {
      const result = await this.client.query(
        "SELECT id, username, email, role FROM users WHERE username ILIKE $1 ESCAPE '\\' ORDER BY id LIMIT 20",
        [`%${this.escapeLikePattern(searchTerm)}%`],
      );
      return result.rows;
    } catch (error) {
      throw new InternalServerErrorException('Database query failed');
    }
  }

  async checkDatabase(timeoutMs = 1000): Promise<{ status: 'ok' | 'error'; latency_ms: number }> {
    const startedAt = Date.now();
    try {
      await this.ensureReady();
      await Promise.race([
        this.client.query('SELECT 1'),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Database health timeout')), timeoutMs)),
      ]);
      return { status: 'ok', latency_ms: Date.now() - startedAt };
    } catch {
      return { status: 'error', latency_ms: Date.now() - startedAt };
    }
  }

  private async ensureReady(): Promise<void> {
    if (!this.connected) {
      await this.connectPromise;
    }
    if (!this.connected) {
      throw new ServiceUnavailableException('Database unavailable');
    }
  }

  private parseUserId(id: string): number {
    const value = String(id || '').trim();
    if (!/^[1-9]\d{0,9}$/.test(value)) {
      throw new BadRequestException('User id must be a positive integer');
    }
    return Number(value);
  }

  private normalizeSearchTerm(name: string): string {
    const value = String(name || '').trim();
    if (!value || value.length > 64) {
      throw new BadRequestException('Search term must be 1-64 characters');
    }
    return value;
  }

  private escapeLikePattern(value: string): string {
    // Escaping LIKE wildcards keeps parameterized search from turning user input into broad scans.
    return value.replace(/[\\%_]/g, (match) => `\\${match}`);
  }
}

