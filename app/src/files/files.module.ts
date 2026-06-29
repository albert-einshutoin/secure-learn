import { Module } from '@nestjs/common';
import { FilesController } from './files.controller';
import { FilesService } from './files.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';

@Module({
  controllers: [FilesController],
  providers: [FilesService, EcsLoggerService],
})
export class FilesModule {}

