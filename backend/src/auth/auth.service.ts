import {
  Injectable,
  InternalServerErrorException,
  OnModuleInit,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { PrismaService } from '../prisma/prisma.service';
import {
  getJwtSecret,
  validateJwtConfig,
  JWT_DEFAULT_ALGORITHM,
  JWT_DEFAULT_EXPIRY,
} from './auth.config';

export interface UserPayload {
  sub: string;
  username: string;
  role: string;
  email: string;
}

@Injectable()
export class AuthService implements OnModuleInit {
  constructor(private readonly prisma: PrismaService) {}

  onModuleInit() {
    // Enforces fatal fail-at-startup in production if JWT_SECRET is missing or insecure
    validateJwtConfig(process.env);
  }

  async generateToken(
    payload: Partial<UserPayload> = {},
    expiresIn: string = process.env.JWT_EXPIRES_IN || JWT_DEFAULT_EXPIRY,
  ) {
    let secret: string;
    try {
      secret = getJwtSecret(process.env);
    } catch (err: any) {
      throw new InternalServerErrorException(
        `Token issuance disabled: ${err.message || 'JWT secret is not configured.'}`,
      );
    }

    // Lookup user in DB if exists, otherwise fallback to seed defaults
    const whereConditions: any[] = [];
    if (payload.sub) whereConditions.push({ id: payload.sub });
    if (payload.username) whereConditions.push({ username: payload.username });

    let dbUser = whereConditions.length > 0
      ? await this.prisma.user.findFirst({ where: { OR: whereConditions } })
      : null;

    if (!dbUser && payload.username) {
      // Auto-create for demo/test if doesn't exist
      try {
        dbUser = await this.prisma.user.create({
          data: {
            id: payload.sub || `user-${payload.username}`,
            userId: `${payload.username}-cuid`,
            username: payload.username,
            email: payload.email || `${payload.username}@soc.platform.local`,
            role: (payload.role as any) || 'SOC_ANALYST',
            isActive: true,
          },
        });
      } catch {
        dbUser = await this.prisma.user.findFirst({
          where: { username: payload.username },
        });
      }
    }

    const userPayload: UserPayload = {
      sub: dbUser?.id || payload.sub || 'user-analyst-01',
      username: dbUser?.username || payload.username || 'soc_analyst',
      role: dbUser?.role || payload.role || 'SOC_ANALYST',
      email: dbUser?.email || payload.email || 'analyst@soc.platform.local',
    };

    const token = jwt.sign(userPayload, secret, {
      algorithm: JWT_DEFAULT_ALGORITHM,
      expiresIn,
    });

    const parsedSeconds = this.parseExpiryToSeconds(expiresIn);

    return {
      access_token: token,
      token_type: 'Bearer',
      expires_in: parsedSeconds,
      user: userPayload,
    };
  }

  private parseExpiryToSeconds(expiryStr: string): number {
    if (typeof expiryStr !== 'string') return 900;
    const match = expiryStr.match(/^(\d+)([smhd])?$/);
    if (!match) return 900;
    const val = parseInt(match[1], 10);
    const unit = match[2];
    switch (unit) {
      case 's':
        return val;
      case 'm':
        return val * 60;
      case 'h':
        return val * 3600;
      case 'd':
        return val * 86400;
      default:
        return val;
    }
  }
}
