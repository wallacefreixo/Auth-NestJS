import {
  Body,
  Controller,
  Post,
  Res,
  Req,
  UseGuards,
  Get,
  ForbiddenException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Throttle } from '@nestjs/throttler';
import { Response, Request } from 'express';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';
import { AuthService } from './auth.service';
import {
  ACCESS_COOKIE_NAME,
  LIMIT_REQUEST_BY_IP,
  ONE_MINUTES_IN_MILLISECONDS,
  REFRESH_COOKIE_NAME,
} from './constants';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private config: ConfigService,
    private jwtService: JwtService,
  ) {}

  private cookieOptions() {
    const isProd = this.config.get('NODE_ENV') === 'production';
    return {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      domain: this.config.get('COOKIE_DOMAIN'),
      path: '/',
    } as any;
  }

  private sevenDaysToMilliseconds(): number {
    return 7 * 24 * 1000 * 60 * 60;
  }

  private fiftenMinutesToMilliseconds(): number {
    return 15 * 1000 * 60;
  }

  @Post('login')
  @Throttle({ default: { limit: LIMIT_REQUEST_BY_IP, ttl: ONE_MINUTES_IN_MILLISECONDS } })
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const { accessToken, refreshToken, userId } = await this.authService.login(
      dto.email,
      dto.password,
    );

    res.cookie(ACCESS_COOKIE_NAME, accessToken, {
      ...this.cookieOptions(),
      maxAge: this.fiftenMinutesToMilliseconds(),
    });

    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      ...this.cookieOptions(),
      maxAge: this.sevenDaysToMilliseconds(),
    });

    return { userId };
  }

  @Post('register')
  async register(@Body() dto: RegisterDto) {
    const user = await this.authService.register(dto);
    return { message: 'Usuário cadastrado', userId: user.id };
  }

  @Post('refresh')
  @Throttle({ default: { limit: LIMIT_REQUEST_BY_IP, ttl: ONE_MINUTES_IN_MILLISECONDS } })
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
    if (!refreshToken) throw new ForbiddenException('Sem refresh token');

    let payload;
    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.config.get('JWT_REFRESH_SECRET'),
      });
    } catch (err) {
      throw new ForbiddenException('Refresh token inválido');
    }

    const tokens = await this.authService.refreshTokens(payload.sub, refreshToken);

    res.cookie(ACCESS_COOKIE_NAME, tokens.accessToken, {
      ...this.cookieOptions(),
      maxAge: this.fiftenMinutesToMilliseconds(),
    });

    res.cookie(REFRESH_COOKIE_NAME, tokens.refreshToken, {
      ...this.cookieOptions(),
      maxAge: this.sevenDaysToMilliseconds(),
    });

    return { ok: true };
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const user = req.user as any;
    if (!user) throw new ForbiddenException();

    const refreshToken = req.cookies[REFRESH_COOKIE_NAME];
    if (refreshToken) {
      try {
        const payload = await this.jwtService.verifyAsync(refreshToken, {
          secret: this.config.get('JWT_REFRESH_SECRET'),
        });
        const jti = payload.jti;
        if (jti) {
          await this.authService.revokeRefreshJti(jti);
        }
      } catch {
        throw new ForbiddenException('Sem refresh token');
      }
    }

    await this.authService.logout(user.sub);
    res.clearCookie(ACCESS_COOKIE_NAME, this.cookieOptions());
    res.clearCookie(REFRESH_COOKIE_NAME, this.cookieOptions());

    return { ok: true };
  }

  @Get('csrf')
  getCsrf(@Req() req: Request) {
    return { csrfToken: req.csrfToken() };
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  getProfile() {
    return { message: 'Você acessou uma rota protegida!' };
  }
}
