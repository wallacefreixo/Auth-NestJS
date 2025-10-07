import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
  Inject,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcrypt';
import { Users } from '@/users/users.entity';
import { UsersService } from '@/users/users.service';
import { RegisterDto } from './dto/register.dto';
import { SALT_ROUNDS } from './constants';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private config: ConfigService,
    @Inject('REDIS_CLIENT') private readonly redisClient: Redis,
  ) {}

  private makeRedisKeyForJti(jti: string) {
    return `refresh_jti:${jti}`;
  }

  private sevenDaysToSeconds(): number {
    return 7 * 24 * 60 * 60;
  }

  async validateUser(email: string, password: string): Promise<Users> {
    const user = await this.usersService.findByEmail(email);
    if (!user) return null;
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return null;
    return user;
  }

  async generateTokens(userId: string, email: string) {
    const payload = { sub: userId, email };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.config.get('JWT_ACCESS_SECRET'),
      expiresIn: this.config.get('JWT_ACCESS_EXPIRES_IN'),
    });

    const jti = uuidv4();
    const refreshPayload = { ...payload, jti };
    const refreshToken = await this.jwtService.signAsync(refreshPayload, {
      secret: this.config.get('JWT_REFRESH_SECRET'),
      expiresIn: this.config.get('JWT_REFRESH_EXPIRES_IN'),
    });

    const ttlSeconds = this.sevenDaysToSeconds();
    await this.redisClient.set(this.makeRedisKeyForJti(jti), userId, 'EX', ttlSeconds);

    return { accessToken, refreshToken, jti };
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);
    if (!user) throw new UnauthorizedException('Credenciais inválidas');

    const tokens = await this.generateTokens(user.id, user.email);
    const refreshHash = await bcrypt.hash(tokens.refreshToken, SALT_ROUNDS);
    await this.usersService.setCurrentRefreshTokenHash(user.id, refreshHash);

    return {
      userId: user.id,
      ...tokens,
    };
  }

  async register(dto: RegisterDto) {
    const existing = await this.usersService.findByEmail(dto.email);
    if (existing) {
      throw new HttpException('Email já registrado', HttpStatus.CONFLICT);
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);
    const user = await this.usersService.create(dto.email, passwordHash);
    return user;
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('Sem refresh token válido');

    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.config.get('JWT_REFRESH_SECRET'),
      });
    } catch (err) {
      throw new UnauthorizedException('Refresh token inválido');
    }

    const jti = payload.jti;
    if (!jti) throw new UnauthorizedException('Refresh token sem jti');

    const redisKey = this.makeRedisKeyForJti(jti);
    const storedUserId = await this.redisClient.get(redisKey);
    if (!storedUserId || storedUserId !== userId) {
      throw new UnauthorizedException('Refresh token inválido ou revogado');
    }

    await this.redisClient.del(redisKey);

    const tokens = await this.generateTokens(user.id, user.email);

    return tokens;
  }

  async logout(userId: string) {
    await this.usersService.setCurrentRefreshTokenHash(userId, null);
  }

  async revokeRefreshJti(jti: string) {
    await this.redisClient.del(this.makeRedisKeyForJti(jti));
  }
}
