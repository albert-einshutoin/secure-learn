import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';
import { UsersService } from './users/users.service';

@Controller()
export class AppController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  root() {
    return {
      service: 'soc-lab-app',
      status: 'ok',
    };
  }

  @Get('health')
  health() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
    };
  }

  @Get('health/ready')
  async ready(@Res({ passthrough: true }) response: Response) {
    const database = await this.usersService.checkDatabase();
    const ready = database.status === 'ok';

    if (!ready) {
      response.status(503);
    }

    return {
      status: ready ? 'ok' : 'degraded',
      timestamp: new Date().toISOString(),
      checks: {
        database,
      },
    };
  }
}
