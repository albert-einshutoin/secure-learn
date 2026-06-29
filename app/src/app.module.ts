import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { FilesModule } from './files/files.module';
import { AppController } from './app.controller';
import { LoggingMiddleware } from './common/logging/logging.middleware';
import { EcsLoggerService } from './common/logging/ecs-logger.service';

@Module({
  imports: [AuthModule, UsersModule, FilesModule],
  controllers: [AppController],
  providers: [EcsLoggerService],
  exports: [EcsLoggerService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggingMiddleware).forRoutes('*');
  }
}

