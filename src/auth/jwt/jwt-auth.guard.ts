import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { ACCESS_COOKIE_NAME } from '../constants';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    const ctx = context.switchToHttp();
    const req = ctx.getRequest<Request>();
    const cookieToken = req.cookies?.[ACCESS_COOKIE_NAME];
    if (cookieToken && !req.headers['authorization']) {
      req.headers['authorization'] = `Bearer ${cookieToken}`;
    }
    return super.canActivate(context);
  }
}
