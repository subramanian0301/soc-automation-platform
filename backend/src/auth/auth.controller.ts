import {
  Controller,
  Post,
  Get,
  Body,
  Request,
  ForbiddenException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Public } from './public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  async login(@Body() body?: { username?: string; password?: string }) {
    if (
      process.env.NODE_ENV === 'production' &&
      process.env.ALLOW_DEMO_LOGIN !== 'true'
    ) {
      throw new ForbiddenException(
        'Public mock login endpoint is disabled in production environments. An external identity provider is required.',
      );
    }
    const username = body?.username || 'soc_analyst';
    return this.authService.generateToken({ username });
  }

  @Public()
  @Get('demo-token')
  async getDemoToken() {
    if (
      process.env.NODE_ENV === 'production' &&
      process.env.ALLOW_DEMO_TOKEN !== 'true'
    ) {
      throw new ForbiddenException(
        'Demo token issuance is disabled in production environments. Please authenticate via standard enterprise credentials.',
      );
    }
    return this.authService.generateToken({
      username: 'demo_analyst',
      role: 'SOC_ANALYST',
    });
  }

  @Get('me')
  async getProfile(@Request() req: any) {
    return {
      authenticated: true,
      user: req.user,
    };
  }
}
