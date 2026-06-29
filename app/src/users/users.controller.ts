import {
  Controller,
  Get,
  Query,
  Req,
  HttpException,
  HttpStatus,
  InternalServerErrorException,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { UsersService } from './users.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';
import { getClientIp } from '../common/network/client-ip';
import { toErrorMessage } from '../common/errors/error-message';
import { BearerAuthGuard, AuthenticatedRequest } from '../common/auth/bearer-auth.guard';
import { Roles } from '../common/auth/roles.decorator';
import { RolesGuard } from '../common/auth/roles.guard';

@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly logger: EcsLoggerService,
  ) {}

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
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.logError(sourceIp, '/users', toErrorMessage(error));
      throw new InternalServerErrorException('Database query failed');
    }
  }

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
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.logError(sourceIp, '/users/search', toErrorMessage(error));
      throw new InternalServerErrorException('Database query failed');
    }
  }

  @Get('admin/audit')
  @UseGuards(BearerAuthGuard, RolesGuard)
  @Roles('admin')
  async adminAudit(@Req() req: AuthenticatedRequest) {
    return {
      status: 'ok',
      viewer: req.user.username,
      checks: ['parameterized-users-query', 'path-boundary-files', 'role-guard'],
    };
  }
}

