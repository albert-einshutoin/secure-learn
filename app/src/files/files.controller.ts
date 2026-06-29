import { Controller, Get, Param, Req, HttpException, HttpStatus } from '@nestjs/common';
import { Request } from 'express';
import { FilesService } from './files.service';
import { EcsLoggerService } from '../common/logging/ecs-logger.service';
import { getClientIp } from '../common/network/client-ip';

@Controller('files')
export class FilesController {
  constructor(
    private readonly filesService: FilesService,
    private readonly logger: EcsLoggerService,
  ) {}

  /**
   * Get file contents - Vulnerable to Path Traversal (S5)
   * The path parameter is not properly sanitized
   * Example attack: /files/..%2F..%2Fetc%2Fpasswd
   */
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
      this.logger.logError(sourceIp, `/files/${filePath}`, error.message);
      throw new HttpException(error.message, HttpStatus.NOT_FOUND);
    }
  }
}

