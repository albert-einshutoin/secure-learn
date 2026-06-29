import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, EcsLoggerService],
  exports: [AuthService],
})
export class AuthModule {}

