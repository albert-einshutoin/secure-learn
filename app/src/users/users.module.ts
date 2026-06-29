import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';

@Module({
  controllers: [UsersController],
  providers: [UsersService, EcsLoggerService],
})
export class UsersModule {}

