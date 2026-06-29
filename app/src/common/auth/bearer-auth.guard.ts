import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { AuthenticatedUser, AuthService } from '../../auth/auth.service';

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

@Injectable()
export class BearerAuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const header = request.headers.authorization || '';
    const [scheme, token] = header.split(' ');

    if (scheme !== 'Bearer' || !token) {
      throw new UnauthorizedException('Missing bearer token');
    }

    const user = this.authService.verifyAccessToken(token);
    if (!user) {
      throw new UnauthorizedException('Invalid bearer token');
    }

    request.user = user;
    return true;
  }
}
