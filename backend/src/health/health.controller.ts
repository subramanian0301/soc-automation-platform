import { Controller, Get } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Public } from '../auth/public.decorator';

@Public()
@Controller('health')
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  async check() {
    let dbStatus = 'disconnected';
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      dbStatus = 'connected';
    } catch (error) {
      dbStatus = `disconnected (${error.message || 'database server unreachable'})`;
    }

    return {
      status: 'ok',
      service: 'SOC Security Platform Backend',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      database: dbStatus,
    };
  }
}
