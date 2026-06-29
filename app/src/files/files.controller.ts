import {
  Controller,
  Get,
  Param,
  Req,
  HttpException,
  HttpStatus,
  InternalServerErrorException,
} from '@nestjs/common';
import { Request } from 'express';
import { FilesService } from './files.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';
import { getClientIp } from '../common/network/client-ip';
import { toErrorMessage } from '../common/errors/error-message';

@Controller('files')
export class FilesController {
  constructor(
    private readonly filesService: FilesService,
    private readonly logger: EcsLoggerService,
  ) {}

  @Get('*path')
  async getFile(@Param('path') pathParam: string | string[], @Req() req: Request) {
    const filePath = Array.isArray(pathParam) ? pathParam.join('/') : pathParam;
    const sourceIp = getClientIp(req);

    if (!filePath) {
      throw new HttpException('File path is required', HttpStatus.BAD_REQUEST);
    }

    // Log potential path traversal attempts
    if (filePath.includes('..') || filePath.includes('%2e') || filePath.includes('%2E')) {
      this.logger.logError(
        sourceIp,
        `/files/${filePath}`,
        `Path traversal attempt detected: ${filePath}`,
      );
    }

    try {
      const content = await this.filesService.readFile(filePath);
      return { path: filePath, content };
    } catch (error) {
      this.logger.logError(sourceIp, `/files/${filePath}`, toErrorMessage(error));
      if (error instanceof HttpException) {
        throw error;
      }
      throw new InternalServerErrorException('File access failed');
    }
  }
}

