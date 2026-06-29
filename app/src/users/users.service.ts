import { Injectable } from '@nestjs/common';
import { Client } from 'pg';

@Injectable()
export class UsersService {
  private client: Client;

  constructor() {
    this.client = new Client({
      host: process.env.DB_HOST || 'db',
      port: parseInt(process.env.DB_PORT || '5432'),
      user: process.env.DB_USER || 'soclab',
      password: process.env.DB_PASS || 'soclab_password',
      database: process.env.DB_NAME || 'soclab',
    });
    this.connect();
  }

  private async connect() {
    try {
      await this.client.connect();
      console.log('Connected to PostgreSQL database');
    } catch (error) {
      console.error('Failed to connect to database:', error);
      // Retry connection after 5 seconds
      setTimeout(() => this.connect(), 5000);
    }
  }

  /**
   * VULNERABLE: SQL Injection
   * The id parameter is directly concatenated into the query
   * Example attack: ?id=1 OR 1=1
   * Example attack: ?id=1; DROP TABLE users; --
   */
  async findById(id: string): Promise<any> {
    // INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
    const query = `SELECT id, username, email, role FROM users WHERE id = ${id}`;
    console.log('Executing query:', query);
    
    try {
      const result = await this.client.query(query);
      return result.rows[0];
    } catch (error) {
      throw error;
    }
  }

  /**
   * VULNERABLE: SQL Injection
   * The name parameter is directly concatenated into the query
   * Example attack: ?name=' OR '1'='1
   */
  async searchByName(name: string): Promise<any[]> {
    // INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
    const query = `SELECT id, username, email, role FROM users WHERE username LIKE '%${name}%'`;
    console.log('Executing query:', query);
    
    try {
      const result = await this.client.query(query);
      return result.rows;
    } catch (error) {
      throw error;
    }
  }
}

