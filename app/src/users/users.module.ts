import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';
import { AuthModule } from '../auth/auth.module';
import { BearerAuthGuard } from '../common/auth/bearer-auth.guard';
import { RolesGuard } from '../common/auth/roles.guard';

@Module({
  imports: [AuthModule],
  controllers: [UsersController],
  providers: [UsersService, EcsLoggerService, BearerAuthGuard, RolesGuard],
  exports: [UsersService],
})
export class UsersModule {}

