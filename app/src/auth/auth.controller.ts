import { Controller, Post, Body, Req, HttpException, HttpStatus } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';
import { getClientIp } from '../common/network/client-ip';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly logger: EcsLoggerService,
  ) {}

  /**
   * Login endpoint - Vulnerable to brute force (S2)
   * No rate limiting at endpoint level, relies on Fail2ban
   */
  @Post('login')
  async login(
    @Body('username') username: string,
    @Body('password') password: string,
    @Req() req: Request,
  ) {
    const sourceIp = getClientIp(req);

    if (!username || !password) {
      this.logger.logAuth('login_failed', sourceIp, username);
      throw new HttpException('Invalid credentials', HttpStatus.BAD_REQUEST);
    }

    const result = await this.authService.validateUser(username, password);

    if (result) {
      this.logger.logAuth('login_success', sourceIp, username);
      return { message: 'Login successful', user: result };
    } else {
      this.logger.logAuth('login_failed', sourceIp, username);
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }
  }
}

