import {
  Controller,
  Post,
  Get,
  Param,
  Query,
  Body,
  Request,
  UseInterceptors,
  UploadedFile,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { AnalysisService } from './analysis.service';

@Controller('analyses')
export class AnalysisController {
  constructor(private readonly analysisService: AnalysisService) {}

  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  async uploadFile(
    @UploadedFile() file: Express.Multer.File,
    @Request() req: any,
  ) {
    if (!file) {
      throw new BadRequestException(
        'No file provided in form-data payload (field name "file").',
      );
    }
    return this.analysisService.processUpload(file, req.user);
  }

  @Get()
  async getAllAnalyses(@Request() req: any) {
    return this.analysisService.getAllAnalyses(req.user);
  }

  @Get(':analysisId')
  async getAnalysisById(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getAnalysisById(analysisId, req.user);
  }

  @Get(':analysisId/siem')
  async getSiemEventsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
    @Query('severity') severity?: string,
    @Query('eventType') eventType?: string,
    @Query('sourceIp') sourceIp?: string,
    @Query('destIp') destIp?: string,
    @Query('search') search?: string,
  ) {
    return this.analysisService.getSiemEventsByAnalysisId(
      analysisId,
      {
        severity,
        eventType,
        sourceIp,
        destIp,
        search,
      },
      req.user,
    );
  }

  @Get(':analysisId/iocs')
  async getIocsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
    @Query('type') type?: string,
    @Query('category') category?: string,
    @Query('search') search?: string,
  ) {
    return this.analysisService.getIocsByAnalysisId(
      analysisId,
      {
        type,
        category,
        search,
      },
      req.user,
    );
  }

  @Get(':analysisId/threat-intel')
  async getThreatIntelByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getThreatIntelByAnalysisId(analysisId, req.user);
  }

  @Get(':analysisId/mitre')
  async getMitreTechniquesByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getMitreTechniquesByAnalysisId(
      analysisId,
      req.user,
    );
  }

  @Get(':analysisId/behavior')
  async getBehaviorEventsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getBehaviorEventsByAnalysisId(
      analysisId,
      req.user,
    );
  }

  @Get(':analysisId/sandbox')
  async getSandboxResultsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getSandboxResultsByAnalysisId(
      analysisId,
      req.user,
    );
  }

  @Get(':analysisId/incidents')
  async getIncidentsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getIncidentsByAnalysisId(analysisId, req.user);
  }

  @Post(':analysisId/incidents')
  async createAnalystIncident(
    @Param('analysisId') analysisId: string,
    @Body()
    dto: {
      title: string;
      severity?: any;
      status?: string;
      reason?: string;
      assignedTo?: string;
    },
    @Request() req: any,
  ) {
    return this.analysisService.createAnalystIncident(analysisId, dto, req.user);
  }

  @Get(':analysisId/cases')
  async getCasesByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getCasesByAnalysisId(analysisId, req.user);
  }

  @Post(':analysisId/cases')
  async createAnalystCase(
    @Param('analysisId') analysisId: string,
    @Body()
    dto: {
      title: string;
      status?: string;
      priority?: string;
      summary?: string;
    },
    @Request() req: any,
  ) {
    return this.analysisService.createAnalystCase(analysisId, dto, req.user);
  }

  @Get(':analysisId/soar')
  async getSoarExecutionsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getSoarExecutionsByAnalysisId(
      analysisId,
      req.user,
    );
  }

  @Post(':analysisId/soar')
  async createAnalystSoarAction(
    @Param('analysisId') analysisId: string,
    @Body()
    dto: {
      actionName: string;
      description?: string;
      actionType?: string;
      target?: string;
      status?: any;
      triggeredBy?: string;
      performedBy?: string;
      isSimulation?: boolean;
      confirmed?: boolean;
      isConfirmed?: boolean;
    },
    @Request() req: any,
  ) {
    return this.analysisService.createAnalystSoarAction(
      analysisId,
      dto,
      req.user,
    );
  }

  @Get(':analysisId/assets')
  async getAssetsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getAssetsByAnalysisId(analysisId, req.user);
  }

  @Post(':analysisId/assets')
  async createAnalystAsset(
    @Param('analysisId') analysisId: string,
    @Body()
    dto: {
      assetName?: string;
      hostname?: string;
      ipAddress?: string;
      macAddress?: string;
      assetType?: string;
      criticality?: string;
      operatingSystem?: string;
      owner?: string;
      status?: string;
      source?: string;
      description?: string;
      evidence?: string;
    },
    @Request() req: any,
  ) {
    return this.analysisService.createAnalystAsset(analysisId, dto, req.user);
  }

  @Get(':analysisId/endpoints')
  async getEndpointsByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getEndpointsByAnalysisId(analysisId, req.user);
  }

  @Post(':analysisId/endpoints')
  async createAnalystEndpoint(
    @Param('analysisId') analysisId: string,
    @Body()
    dto: {
      hostname?: string;
      ipAddress?: string;
      osVersion?: string;
      operatingSystem?: string;
      user?: string;
      agentStatus?: string;
      status?: string;
      endpointType?: string;
      source?: string;
      evidence?: string;
    },
    @Request() req: any,
  ) {
    return this.analysisService.createAnalystEndpoint(analysisId, dto, req.user);
  }

  @Get(':analysisId/vulnerabilities')
  async getVulnerabilitiesByAnalysisId(
    @Param('analysisId') analysisId: string,
    @Request() req: any,
  ) {
    return this.analysisService.getVulnerabilitiesByAnalysisId(
      analysisId,
      req.user,
    );
  }

  @Post(':analysisId/vulnerabilities')
  async createAnalystVulnerability(
    @Param('analysisId') analysisId: string,
    @Body()
    dto: {
      cveId?: string;
      vulnerabilityId?: string;
      title?: string;
      name?: string;
      cvssScore?: number;
      severity?: string;
      description?: string;
      affectedAsset?: string;
      packageName?: string;
      installedVersion?: string;
      fixedVersion?: string;
      status?: string;
      remediation?: string;
      source?: string;
      evidence?: string;
    },
    @Request() req: any,
  ) {
    return this.analysisService.createAnalystVulnerability(
      analysisId,
      dto,
      req.user,
    );
  }
}
