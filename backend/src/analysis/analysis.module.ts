import { Module } from '@nestjs/common';
import { AnalysisController } from './analysis.controller';
import { AnalysisService } from './analysis.service';
import { UploadModule } from '../upload/upload.module';
import { ParserModule } from '../parser/parser.module';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule, UploadModule, ParserModule],
  controllers: [AnalysisController],
  providers: [AnalysisService],
  exports: [AnalysisService],
})
export class AnalysisModule {}
