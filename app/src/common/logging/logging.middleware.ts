import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { EcsLoggerService } from './ecs-logger.service';
import { getClientIp } from '../network/client-ip';

@Injectable()
export class LoggingMiddleware implements NestMiddleware {
  private readonly logger = new EcsLoggerService();

  use(req: Request, res: Response, next: NextFunction) {
    const sourceIp = getClientIp(req);

    res.on('finish', () => {
      this.logger.logAccess(
        req.method,
        req.originalUrl,
        res.statusCode,
        sourceIp,
      );
    });

    next();
  }
}

