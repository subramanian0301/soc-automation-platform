import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient, UserRole } from '@prisma/client';

export interface SeedUser {
  id: string;
  userId: string;
  username: string;
  email: string;
  role: UserRole;
  isActive: boolean;
}

export const SYSTEM_SEED_USERS: SeedUser[] = [
  {
    id: 'test-user-id',
    userId: 'test_analyst_01',
    username: 'test_analyst',
    email: 'test_analyst@soc.platform.local',
    role: UserRole.ADMIN,
    isActive: true,
  },
  {
    id: 'demo-user-id',
    userId: 'demo_analyst_01',
    username: 'demo_analyst',
    email: 'demo_analyst@soc.platform.local',
    role: UserRole.SOC_ANALYST,
    isActive: true,
  },
  {
    id: 'user-analyst-01',
    userId: 'soc_analyst_01',
    username: 'soc_analyst',
    email: 'analyst@soc.platform.local',
    role: UserRole.SOC_ANALYST,
    isActive: true,
  },
  {
    id: 'user-analyst-alpha',
    userId: 'analyst_alpha_01',
    username: 'analyst_alpha',
    email: 'alpha@soc.platform.local',
    role: UserRole.SOC_ANALYST,
    isActive: true,
  },
  {
    id: 'user-analyst-beta',
    userId: 'analyst_beta_01',
    username: 'analyst_beta',
    email: 'beta@soc.platform.local',
    role: UserRole.SOC_ANALYST,
    isActive: true,
  },
  {
    id: 'admin-user-id',
    userId: 'soc_admin_01',
    username: 'soc_admin',
    email: 'admin@soc.platform.local',
    role: UserRole.ADMIN,
    isActive: true,
  },
  {
    id: 'readonly-user-id',
    userId: 'readonly_analyst_01',
    username: 'readonly_analyst',
    email: 'readonly@soc.platform.local',
    role: UserRole.READONLY_ANALYST,
    isActive: true,
  },
  {
    id: 'deactivated-user-id',
    userId: 'deactivated_user_01',
    username: 'deactivated_analyst',
    email: 'deactivated@soc.platform.local',
    role: UserRole.SOC_ANALYST,
    isActive: false,
  },
];

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit() {
    try {
      await this.$connect();
      await this.seedDefaultUsersAndBackfill();
    } catch (e: any) {
      console.warn('[Prisma] Database connection warning:', e.message);
    }
  }

  async seedDefaultUsersAndBackfill() {
    try {
      for (const u of SYSTEM_SEED_USERS) {
        await this.user.upsert({
          where: { username: u.username },
          update: { role: u.role, isActive: u.isActive },
          create: {
            id: u.id,
            userId: u.userId,
            username: u.username,
            email: u.email,
            role: u.role,
            isActive: u.isActive,
          },
        });
      }

      // Backfill any legacy unassigned analyses to test-user-id for test suite backward compatibility
      await this.analysis.updateMany({
        where: { userId: null },
        data: { userId: 'test-user-id' },
      });
    } catch (e: any) {
      console.warn('[Prisma] User seeding warning:', e.message);
    }
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
