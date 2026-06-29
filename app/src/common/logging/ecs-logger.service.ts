import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

export interface EcsLog {
  '@timestamp': string;
  'event.module': string;
  'event.category': string;
  'event.action': string;
  'event.outcome': 'success' | 'failure';
  'source.ip': string;
  'url.path'?: string;
  'http.request.method'?: string;
  'http.response.status_code'?: number;
  'user.name'?: string;
  message?: string;
}

@Injectable()
export class EcsLoggerService {
  private readonly logPath: string;
  private readonly authLogPath: string;
  private readonly accessLogPath: string;
  private readonly errorLogPath: string;

  constructor() {
    this.logPath = process.env.LOG_PATH || '/var/log/app';
    this.authLogPath = path.join(this.logPath, 'auth.log');
    this.accessLogPath = path.join(this.logPath, 'access.log');
    this.errorLogPath = path.join(this.logPath, 'error.log');

    // Ensure log directory exists
    if (!fs.existsSync(this.logPath)) {
      fs.mkdirSync(this.logPath, { recursive: true });
    }

    for (const filePath of [this.authLogPath, this.accessLogPath, this.errorLogPath]) {
      if (!fs.existsSync(filePath)) {
        fs.closeSync(fs.openSync(filePath, 'a'));
      }
    }
  }

  private formatLog(log: EcsLog): string {
    return JSON.stringify(log) + '\n';
  }

  private writeLog(filePath: string, log: EcsLog): void {
    try {
      fs.appendFileSync(filePath, this.formatLog(log));
    } catch (error) {
      console.error(`Failed to write log to ${filePath}:`, error);
    }
  }

  logAuth(
    action: 'login_success' | 'login_failed',
    sourceIp: string,
    username?: string,
  ): void {
    const log: EcsLog = {
      '@timestamp': new Date().toISOString(),
      'event.module': 'nestjs',
      'event.category': 'authentication',
      'event.action': action,
      'event.outcome': action === 'login_success' ? 'success' : 'failure',
      'source.ip': sourceIp,
      'user.name': username,
      message: `Authentication ${action} from ${sourceIp} for user ${username || 'unknown'}`,
    };
    this.writeLog(this.authLogPath, log);
  }

  logAccess(
    method: string,
    path: string,
    statusCode: number,
    sourceIp: string,
  ): void {
    const log: EcsLog = {
      '@timestamp': new Date().toISOString(),
      'event.module': 'nestjs',
      'event.category': 'web',
      'event.action': 'access',
      'event.outcome': statusCode < 400 ? 'success' : 'failure',
      'source.ip': sourceIp,
      'url.path': path,
      'http.request.method': method,
      'http.response.status_code': statusCode,
      message: `${method} ${path} - ${statusCode} from ${sourceIp}`,
    };
    this.writeLog(this.accessLogPath, log);
  }

  logSqliAttempt(sourceIp: string, path: string, query: string): void {
    const log: EcsLog = {
      '@timestamp': new Date().toISOString(),
      'event.module': 'nestjs',
      'event.category': 'intrusion_detection',
      'event.action': 'sqli_attempt',
      'event.outcome': 'failure',
      'source.ip': sourceIp,
      'url.path': path,
      message: `SQLi attempt detected from ${sourceIp}: ${query}`,
    };
    this.writeLog(this.errorLogPath, log);
  }

  logError(sourceIp: string, path: string, error: string): void {
    const log: EcsLog = {
      '@timestamp': new Date().toISOString(),
      'event.module': 'nestjs',
      'event.category': 'error',
      'event.action': 'error',
      'event.outcome': 'failure',
      'source.ip': sourceIp,
      'url.path': path,
      message: error,
    };
    this.writeLog(this.errorLogPath, log);
  }
}

