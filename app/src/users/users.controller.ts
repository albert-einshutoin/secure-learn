import { Controller, Get, Query, Req, HttpException, HttpStatus } from '@nestjs/common';
import { Request } from 'express';
import { UsersService } from './users.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';
import { getClientIp } from '../common/network/client-ip';

@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly logger: EcsLoggerService,
  ) {}

  /**
   * Get user by ID - Vulnerable to SQL Injection (S3)
   * The 'id' parameter is directly concatenated into SQL query
   */
  @Get()
  async getUser(@Query('id') id: string, @Req() req: Request) {
    const sourceIp = getClientIp(req);

    if (!id) {
      throw new HttpException('ID parameter is required', HttpStatus.BAD_REQUEST);
    }

    // Detect potential SQLi patterns and log them
    const sqliPatterns = /('|"|;|--|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b)/i;
    if (sqliPatterns.test(id)) {
      this.logger.logSqliAttempt(sourceIp, '/users', id);
    }

    try {
      const user = await this.usersService.findById(id);
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
      return user;
    } catch (error) {
      this.logger.logError(sourceIp, '/users', error.message);
      throw new HttpException(
        'Database error: ' + error.message,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Search users - Also vulnerable to SQLi
   */
  @Get('search')
  async searchUsers(@Query('name') name: string, @Req() req: Request) {
    const sourceIp = getClientIp(req);

    if (!name) {
      throw new HttpException('Name parameter is required', HttpStatus.BAD_REQUEST);
    }

    // Detect potential SQLi patterns
    const sqliPatterns = /('|"|;|--|\bunion\b|\bselect\b|\bdrop\b)/i;
    if (sqliPatterns.test(name)) {
      this.logger.logSqliAttempt(sourceIp, '/users/search', name);
    }

    try {
      return await this.usersService.searchByName(name);
    } catch (error) {
      this.logger.logError(sourceIp, '/users/search', error.message);
      throw new HttpException(
        'Database error: ' + error.message,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}

