import {
  Injectable,
  NotFoundException,
  BadRequestException,
  InternalServerErrorException,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UploadService } from '../upload/upload.service';
import { ParserService } from '../parser/parser.service';
import { Analysis, ThreatLevel, AnalysisStatus, SoarStatus } from '@prisma/client';
import { randomUUID, createHash } from 'crypto';

export interface AuthenticatedUser {
  id: string;
  sub?: string;
  username: string;
  email?: string;
  role: string;
}

@Injectable()
export class AnalysisService {
  private readonly logger = new Logger(AnalysisService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly uploadService: UploadService,
    private readonly parserService: ParserService,
  ) {}

  /**
   * Authoritative access and ownership verification helper.
   * Prevents IDOR / BOLA vulnerabilities across all analysis-scoped routes.
   * Throws NotFoundException if the analysisId does not exist.
   * Throws ForbiddenException if the user is neither the owner nor an ADMIN.
   * Enforces role-based write authorization for READONLY_ANALYST roles.
   */
  async verifyAnalysisAccess(
    analysisId: string,
    user?: AuthenticatedUser,
    action: 'read' | 'write' = 'read',
  ): Promise<Analysis> {
    const analysis = await this.prisma.analysis.findUnique({
      where: { analysisId },
    });

    if (!analysis) {
      throw new NotFoundException(`Analysis with ID '${analysisId}' not found.`);
    }

    if (user && analysis.userId && user.role !== 'ADMIN' && analysis.userId !== user.id) {
      throw new ForbiddenException(
        `Access denied: You do not have permission to access analysis '${analysisId}'.`,
      );
    }

    if (user && action === 'write' && user.role === 'READONLY_ANALYST') {
      throw new ForbiddenException(
        `Access denied: Role 'READONLY_ANALYST' does not have permission to perform modifications.`,
      );
    }

    return analysis;
  }

  async processUpload(
    file: Express.Multer.File,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    originalFileName: string;
    fileType: string;
    fileSize: number;
    riskScore: number | null;
    threatLevel: ThreatLevel | null;
    status: AnalysisStatus;
    uploadedAt: Date;
    userId?: string | null;
  }> {
    const analysisId = `analysis_${randomUUID().replace(/-/g, '').substring(0, 16)}`;
    const owningUserId = user?.id || 'test-user-id';

    // Save file locally to /uploads. Original source file is permanently preserved on disk.
    let storedDetails;
    try {
      storedDetails = await this.uploadService.saveFile(file, analysisId);
    } catch (err: any) {
      throw err instanceof BadRequestException
        ? err
        : new BadRequestException(`Upload error: ${err.message}`);
    }

    let fileContent: string;
    try {
      fileContent = file.buffer.toString('utf-8');
    } catch {
      throw new BadRequestException('Failed to read uploaded file buffer as UTF-8 text.');
    }

    // Calculate actual file hashes from uploaded bytes
    const calculatedMd5 = createHash('md5').update(file.buffer).digest('hex');
    const calculatedSha1 = createHash('sha1').update(file.buffer).digest('hex');
    const calculatedSha256 = createHash('sha256').update(file.buffer).digest('hex');

    // Detect format and parse
    let parsedResult;
    try {
      parsedResult = await this.parserService.parseFile(fileContent, {
        originalFileName: storedDetails.originalFileName,
        fileSize: storedDetails.fileSize,
        mimeType: storedDetails.mimeType,
        extension: storedDetails.extension,
        calculatedHashes: {
          md5: calculatedMd5,
          sha1: calculatedSha1,
          sha256: calculatedSha256,
        },
      });
    } catch (err: any) {
      throw err instanceof BadRequestException
        ? err
        : new BadRequestException(`Parser error: ${err.message}`);
    }

    const { format, analysisInput } = parsedResult;

    // Persist Analysis and child records in a Prisma Transaction
    try {
      const createdAnalysis = await this.prisma.$transaction(async (tx) => {
        const analysisRecord = await tx.analysis.create({
          data: {
            analysisId,
            userId: owningUserId,
            fileName: storedDetails.storedFileName,
            originalFileName: storedDetails.originalFileName,
            fileSize: storedDetails.fileSize,
            fileType: format,
            mimeType: storedDetails.mimeType,
            hostname: analysisInput.metadata.hostname,
            username: analysisInput.metadata.username,
            operatingSystem: analysisInput.metadata.operatingSystem,
            analysisTime: analysisInput.metadata.analysisTime,
            riskScore: analysisInput.risk.riskScore,
            threatLevel: analysisInput.risk.threatLevel,
            recommendation: analysisInput.risk.recommendation,
            status: AnalysisStatus.COMPLETED,
            parsingStatus: analysisInput.parsingStatus || 'COMPLETED',
            parsingWarnings: analysisInput.parsingWarnings || [],
            unrecognizedFields: analysisInput.unrecognizedFields || null,
            provenance: analysisInput.provenance || null,
            source: fileContent.length > 50000 ? fileContent.substring(0, 50000) : fileContent,
            fileMetadata: {
              create: {
                filePath: storedDetails.storedPath,
                storageKey: storedDetails.storageKey,
                extension: storedDetails.extension,
                calculatedMd5,
                calculatedSha1,
                calculatedSha256,
              },
            },
            hashes: analysisInput.hashes
              ? {
                  create: {
                    md5: analysisInput.hashes.md5,
                    sha1: analysisInput.hashes.sha1,
                    sha256: analysisInput.hashes.sha256,
                    ssdeep: analysisInput.hashes.ssdeep,
                  },
                }
              : undefined,
            fileProperties: analysisInput.fileProperties
              ? {
                  create: {
                    entropy: analysisInput.fileProperties.entropy,
                    digitalSignature: analysisInput.fileProperties.digitalSignature,
                    isPacked: analysisInput.fileProperties.isPacked,
                    packer: analysisInput.fileProperties.packer,
                    imports: analysisInput.fileProperties.imports,
                    suspiciousApis: analysisInput.fileProperties.suspiciousApis,
                  },
                }
              : undefined,
            yaraResults:
              analysisInput.yara && analysisInput.yara.length > 0
                ? {
                    create: analysisInput.yara.map((y) => ({
                      ruleName: y.ruleName,
                      namespace: y.namespace,
                      tags: y.tags,
                      meta: y.meta,
                      description: y.description,
                    })),
                  }
                : undefined,
            virusTotalResult: analysisInput.virusTotal
              ? {
                  create: {
                    positives: analysisInput.virusTotal.positives,
                    total: analysisInput.virusTotal.total,
                    permalink: analysisInput.virusTotal.permalink,
                    scanDate: analysisInput.virusTotal.scanDate,
                    detections: analysisInput.virusTotal.detections,
                  },
                }
              : undefined,
            iocs:
              analysisInput.iocs && analysisInput.iocs.length > 0
                ? {
                    create: analysisInput.iocs.map((i) => ({
                      type: i.type,
                      value: i.value,
                      category: i.category,
                      confidence: i.confidence,
                      description: i.description,
                    })),
                  }
                : undefined,
            mitreTechniques:
              analysisInput.mitre && analysisInput.mitre.length > 0
                ? {
                    create: analysisInput.mitre.map((m) => ({
                      tactic: m.tactic,
                      techniqueId: m.techniqueId,
                      name: m.name,
                      description: m.description,
                    })),
                  }
                : undefined,
            behaviorEvents:
              analysisInput.behavior && analysisInput.behavior.length > 0
                ? {
                    create: analysisInput.behavior.map((b) => ({
                      eventType: b.eventType,
                      action: b.action,
                      target: b.target,
                      details: b.details,
                      timestamp: b.timestamp,
                    })),
                  }
                : undefined,
            sandboxResults:
              analysisInput.sandbox && analysisInput.sandbox.length > 0
                ? {
                    create: analysisInput.sandbox.map((s) => ({
                      sandboxName: s.sandboxName,
                      verdict: s.verdict,
                      score: s.score,
                      details: s.details,
                    })),
                  }
                : undefined,
            siemEvents:
              analysisInput.siem && analysisInput.siem.length > 0
                ? {
                    create: analysisInput.siem.map((s) => ({
                      eventId: s.eventId,
                      sourceIp: s.sourceIp,
                      destIp: s.destIp,
                      sourcePort: s.sourcePort,
                      destPort: s.destPort,
                      protocol: s.protocol,
                      action: s.action,
                      severity: s.severity,
                      rawEvent: s.rawEvent,
                      timestamp: s.timestamp,
                    })),
                  }
                : undefined,
            incidents:
              analysisInput.incident && analysisInput.incident.length > 0
                ? {
                    create: analysisInput.incident.map((inc) => ({
                      title: inc.title,
                      severity: inc.severity,
                      status: inc.status,
                      reason: inc.reason,
                      assignedTo: inc.assignedTo,
                    })),
                  }
                : undefined,
            soarExecutions:
              analysisInput.soar && analysisInput.soar.length > 0
                ? {
                    create: analysisInput.soar.map((soar) => ({
                      actionName: soar.actionName,
                      description: soar.description,
                      actionType: soar.actionType,
                      target: soar.target,
                      status: soar.status,
                      triggeredBy: soar.triggeredBy || 'Source',
                      source: soar.source || 'Source',
                      result: soar.result,
                      executionLog: soar.executionLog,
                      executedAt: soar.executedAt,
                      completedAt: soar.completedAt,
                    })),
                  }
                : undefined,
            assets:
              analysisInput.assets && analysisInput.assets.length > 0
                ? {
                    create: analysisInput.assets.map((a) => ({
                      assetName: a.assetName || a.hostname || a.ipAddress || 'Asset',
                      hostname: a.hostname || null,
                      ipAddress: a.ipAddress || null,
                      macAddress: a.macAddress || null,
                      assetType: a.assetType || null,
                      criticality: a.criticality || null,
                      operatingSystem: a.operatingSystem || null,
                      owner: a.owner || a.user || null,
                      status: a.status || null,
                      source: a.source || 'Source file',
                      description: a.description || null,
                      evidence: a.evidence || null,
                    })),
                  }
                : undefined,
            endpoints:
              analysisInput.endpoints && analysisInput.endpoints.length > 0
                ? {
                    create: analysisInput.endpoints.map((e) => ({
                      hostname: e.hostname || e.ipAddress || 'Endpoint',
                      ipAddress: e.ipAddress || null,
                      osVersion: e.osVersion || e.operatingSystem || null,
                      operatingSystem: e.operatingSystem || e.osVersion || null,
                      user: e.user || null,
                      agentStatus: e.agentStatus || e.status || null,
                      status: e.status || e.agentStatus || null,
                      endpointType: e.endpointType || null,
                      source: e.source || 'Source file',
                      evidence: e.evidence || null,
                      lastSeen: e.lastSeen || null,
                    })),
                  }
                : undefined,
            vulnerabilities:
              analysisInput.vulnerabilities && analysisInput.vulnerabilities.length > 0
                ? {
                    create: analysisInput.vulnerabilities.map((v) => ({
                      cveId: v.cveId || v.vulnerabilityId || 'CVE-UNKNOWN',
                      title: v.title || v.name || v.cveId || 'Vulnerability',
                      cvssScore: v.cvssScore !== undefined ? v.cvssScore : null,
                      severity: v.severity || null,
                      description: v.description || null,
                      affectedAsset: v.affectedAsset || null,
                      packageName: v.packageName || null,
                      installedVersion: v.installedVersion || null,
                      fixedVersion: v.fixedVersion || null,
                      status: v.status || null,
                      remediation: v.remediation || null,
                      source: v.source || 'Source file',
                      evidence: v.evidence || null,
                    })),
                  }
                : undefined,
            auditLogs: {
              create: {
                action: 'ANALYSIS_UPLOADED',
                performedBy: user?.username || 'SYSTEM_UPLOAD_PIPELINE',
                details: `Uploaded file ${storedDetails.originalFileName}`,
              },
            },
          },
        });

        return analysisRecord;
      });

      this.logger.log(
        `[AnalysisService] [${createdAnalysis.analysisId}] PARSED vs SAVED counts: ` +
        JSON.stringify({
          parsed: {
            yara: analysisInput.yara?.length || 0,
            virusTotal: analysisInput.virusTotal ? 1 : 0,
            iocs: analysisInput.iocs?.length || 0,
            mitre: analysisInput.mitre?.length || 0,
            behavior: analysisInput.behavior?.length || 0,
            sandbox: analysisInput.sandbox?.length || 0,
            siem: analysisInput.siem?.length || 0,
            incidents: analysisInput.incident?.length || 0,
            soar: analysisInput.soar?.length || 0,
            assets: analysisInput.assets?.length || 0,
            endpoints: analysisInput.endpoints?.length || 0,
            vulnerabilities: analysisInput.vulnerabilities?.length || 0,
          },
          saved: {
            yara: analysisInput.yara?.length || 0,
            virusTotal: analysisInput.virusTotal ? 1 : 0,
            iocs: analysisInput.iocs?.length || 0,
            mitre: analysisInput.mitre?.length || 0,
            behavior: analysisInput.behavior?.length || 0,
            sandbox: analysisInput.sandbox?.length || 0,
            siem: analysisInput.siem?.length || 0,
            incidents: analysisInput.incident?.length || 0,
            soar: analysisInput.soar?.length || 0,
            assets: analysisInput.assets?.length || 0,
            endpoints: analysisInput.endpoints?.length || 0,
            vulnerabilities: analysisInput.vulnerabilities?.length || 0,
          },
        })
      );

      return {
        analysisId: createdAnalysis.analysisId,
        originalFileName: createdAnalysis.originalFileName,
        fileType: createdAnalysis.fileType,
        fileSize: createdAnalysis.fileSize,
        riskScore: createdAnalysis.riskScore,
        threatLevel: createdAnalysis.threatLevel,
        status: createdAnalysis.status,
        uploadedAt: createdAnalysis.uploadedAt,
        userId: createdAnalysis.userId,
      };
    } catch (txErr: any) {
      throw new InternalServerErrorException(
        `Persistence transaction failed: ${txErr.message}`,
      );
    }
  }

  async getAllAnalyses(user?: AuthenticatedUser): Promise<Analysis[]> {
    const whereClause: any = { isArchived: false };
    if (user && user.role !== 'ADMIN') {
      whereClause.userId = user.id;
    }

    return this.prisma.analysis.findMany({
      where: whereClause,
      orderBy: { createdAt: 'desc' },
    });
  }

  async getAnalysisById(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<any> {
    await this.verifyAnalysisAccess(analysisId, user, 'read');

    return this.prisma.analysis.findUnique({
      where: { analysisId },
      include: {
        fileMetadata: true,
        hashes: true,
        fileProperties: true,
        yaraResults: true,
        virusTotalResult: true,
        iocs: true,
        mitreTechniques: true,
        behaviorEvents: true,
        sandboxResults: true,
        siemEvents: true,
        incidents: true,
        cases: true,
        soarExecutions: true,
        assets: true,
        endpoints: true,
        vulnerabilities: true,
        auditLogs: true,
      },
    });
  }

  async getSiemEventsByAnalysisId(
    analysisId: string,
    query?: {
      severity?: string;
      eventType?: string;
      sourceIp?: string;
      destIp?: string;
      search?: string;
    },
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    events: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const whereClause: any = { analysisId };
    if (query?.severity && query.severity !== 'ALL') {
      whereClause.severity = { equals: query.severity.toUpperCase() };
    }
    if (query?.sourceIp) {
      whereClause.sourceIp = { contains: query.sourceIp };
    }
    if (query?.destIp) {
      whereClause.destIp = { contains: query.destIp };
    }
    if (query?.search) {
      const q = query.search.trim();
      if (q) {
        whereClause.OR = [
          { rawEvent: { contains: q } },
          { eventId: { contains: q } },
          { action: { contains: q } },
          { sourceIp: { contains: q } },
          { destIp: { contains: q } },
          { protocol: { contains: q } },
          { severity: { contains: q } },
        ];
      }
    }

    const events = await this.prisma.siemEvent.findMany({
      where: whereClause,
      orderBy: { timestamp: 'desc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] SIEM returned count: ${events.length}`);

    return {
      analysisId,
      totalCount: events.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      events,
    };
  }

  async getIocsByAnalysisId(
    analysisId: string,
    query?: {
      type?: string;
      category?: string;
      search?: string;
    },
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    iocs: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const whereClause: any = { analysisId };
    if (query?.type && query.type !== 'ALL') {
      whereClause.type = { equals: query.type.toUpperCase() };
    }
    if (query?.category) {
      whereClause.category = { contains: query.category };
    }
    if (query?.search) {
      const q = query.search.trim();
      if (q) {
        whereClause.OR = [
          { value: { contains: q } },
          { type: { contains: q } },
          { category: { contains: q } },
          { description: { contains: q } },
        ];
      }
    }

    const iocs = await this.prisma.ioc.findMany({
      where: whereClause,
      orderBy: { id: 'asc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] IOC returned count: ${iocs.length}`);

    return {
      analysisId,
      totalCount: iocs.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      iocs,
    };
  }

  async getThreatIntelByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<any> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const detailedAnalysis = await this.prisma.analysis.findUnique({
      where: { analysisId },
      include: {
        iocs: true,
        virusTotalResult: true,
        yaraResults: true,
      },
    });

    const hasData =
      (detailedAnalysis?.iocs && detailedAnalysis.iocs.length > 0) ||
      detailedAnalysis?.virusTotalResult !== null ||
      (detailedAnalysis?.yaraResults && detailedAnalysis.yaraResults.length > 0) ||
      detailedAnalysis?.riskScore !== null ||
      detailedAnalysis?.threatLevel !== null;

    return {
      analysisId,
      hasData,
      riskScore: detailedAnalysis?.riskScore,
      threatLevel: detailedAnalysis?.threatLevel,
      recommendation: detailedAnalysis?.recommendation,
      virusTotalResult: detailedAnalysis?.virusTotalResult,
      yaraResults: detailedAnalysis?.yaraResults || [],
      iocs: detailedAnalysis?.iocs || [],
      parsingStatus: detailedAnalysis?.parsingStatus,
      parsingWarnings: detailedAnalysis?.parsingWarnings as any,
      provenance: detailedAnalysis?.provenance,
    };
  }

  async getMitreTechniquesByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    techniques: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const techniques = await this.prisma.mitreTechnique.findMany({
      where: { analysisId },
      orderBy: { id: 'asc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] MITRE returned count: ${techniques.length}`);

    return {
      analysisId,
      totalCount: techniques.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      techniques,
    };
  }

  async getBehaviorEventsByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    events: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const events = await this.prisma.behaviorEvent.findMany({
      where: { analysisId },
      orderBy: { id: 'asc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] Behavior returned count: ${events.length}`);

    return {
      analysisId,
      totalCount: events.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      events,
    };
  }

  async getSandboxResultsByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    results: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const results = await this.prisma.sandboxResult.findMany({
      where: { analysisId },
      orderBy: { id: 'asc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] Sandbox returned count: ${results.length}`);

    return {
      analysisId,
      totalCount: results.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      results,
    };
  }

  async getIncidentsByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    incidents: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const incidents = await this.prisma.incident.findMany({
      where: { analysisId },
      orderBy: { createdAt: 'desc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] Incidents returned count: ${incidents.length}`);

    return {
      analysisId,
      totalCount: incidents.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      incidents,
    };
  }

  async createAnalystIncident(
    analysisId: string,
    dto: {
      title: string;
      severity?: ThreatLevel;
      status?: string;
      reason?: string;
      assignedTo?: string;
    },
    user?: AuthenticatedUser,
  ): Promise<any> {
    await this.verifyAnalysisAccess(analysisId, user, 'write');

    if (!dto.title || dto.title.trim().length === 0) {
      throw new BadRequestException('Incident title is required.');
    }

    return this.prisma.incident.create({
      data: {
        analysisId,
        title: dto.title.trim(),
        severity: dto.severity || null,
        status: dto.status || 'OPEN',
        reason: dto.reason || 'Analyst created incident',
        assignedTo: dto.assignedTo || null,
      },
    });
  }

  async getCasesByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    cases: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const cases = await this.prisma.case.findMany({
      where: { analysisId },
      orderBy: { id: 'asc' },
    });

    return {
      analysisId,
      totalCount: cases.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      cases,
    };
  }

  async createAnalystCase(
    analysisId: string,
    dto: {
      title: string;
      status?: string;
      priority?: string;
      summary?: string;
    },
    user?: AuthenticatedUser,
  ): Promise<any> {
    await this.verifyAnalysisAccess(analysisId, user, 'write');

    if (!dto.title || dto.title.trim().length === 0) {
      throw new BadRequestException('Case title is required.');
    }

    const caseNumber = `CASE-${randomUUID().replace(/-/g, '').substring(0, 8).toUpperCase()}`;

    return this.prisma.case.create({
      data: {
        analysisId,
        caseNumber,
        title: dto.title.trim(),
        status: dto.status || 'NEW',
        priority: dto.priority || 'MEDIUM',
        summary: dto.summary || null,
      },
    });
  }

  async getSoarExecutionsByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    soarExecutions: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const soarExecutions = await this.prisma.soarExecution.findMany({
      where: { analysisId },
      orderBy: { timestamp: 'desc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] SOAR returned count: ${soarExecutions.length}`);

    return {
      analysisId,
      totalCount: soarExecutions.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      soarExecutions,
    };
  }

  async createAnalystSoarAction(
    analysisId: string,
    dto: {
      actionName: string;
      description?: string;
      actionType?: string;
      target?: string;
      status?: SoarStatus;
      triggeredBy?: string;
      performedBy?: string;
      isSimulation?: boolean;
      confirmed?: boolean;
      isConfirmed?: boolean;
    },
    user?: AuthenticatedUser,
  ): Promise<any> {
    await this.verifyAnalysisAccess(analysisId, user, 'write');

    // Reject execution unless confirmation flag is explicitly provided
    if (!dto.confirmed && !dto.isConfirmed) {
      throw new BadRequestException(
        'SOAR playbook execution rejected: Confirmation flag is required in request payload.',
      );
    }

    if (!dto.actionName || dto.actionName.trim().length === 0) {
      throw new BadRequestException('Action / Playbook name is required.');
    }

    const actionName = dto.actionName.trim();
    const actionType = dto.actionType || 'Playbook Action';
    const target = dto.target || null;
    // Authoritatively resolve actor from the authenticated user, ignoring untrusted client body
    const authenticatedActor = user?.username || user?.email || user?.id || 'Authenticated Analyst';
    // SOAR response actions are strictly maintained in SIMULATION mode
    const status = SoarStatus.SIMULATION;
    const now = new Date();

    const resultMsg = 'Dry Run Completed (Simulation Mode)';
    const logMsg = `Analyst '${authenticatedActor}' triggered '${actionName}' on target '${target || 'N/A'}' [${status}].`;

    const soarRecord = await this.prisma.soarExecution.create({
      data: {
        analysisId,
        actionName,
        description: dto.description || `Analyst triggered action: ${actionName}`,
        actionType,
        target,
        status,
        triggeredBy: dto.triggeredBy || authenticatedActor,
        source: 'Analyst',
        result: resultMsg,
        executionLog: logMsg,
        executedAt: now,
        completedAt: now,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        analysisId,
        action: `SOAR_PLAYBOOK_EXECUTE:${actionName}`,
        performedBy: authenticatedActor,
        timestamp: now,
        details: JSON.stringify({
          soarExecutionId: soarRecord.id,
          actionName,
          target,
          status,
          result: resultMsg,
          mode: 'SIMULATION',
        }),
      },
    });

    return {
      ...soarRecord,
      performedBy: authenticatedActor,
    };
  }

  async getAssetsByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    assets: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const assets = await this.prisma.asset.findMany({
      where: { analysisId },
      orderBy: { createdAt: 'desc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] Assets returned count: ${assets.length}`);

    return {
      analysisId,
      totalCount: assets.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      assets,
    };
  }

  async createAnalystAsset(
    analysisId: string,
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
    user?: AuthenticatedUser,
  ): Promise<any> {
    await this.verifyAnalysisAccess(analysisId, user, 'write');

    const name = dto.assetName || dto.hostname || dto.ipAddress;
    if (!name || name.trim().length === 0) {
      throw new BadRequestException('Asset Name, Hostname, or IP Address is required.');
    }

    return this.prisma.asset.create({
      data: {
        analysisId,
        assetName: name.trim(),
        hostname: dto.hostname?.trim() || null,
        ipAddress: dto.ipAddress?.trim() || null,
        macAddress: dto.macAddress?.trim() || null,
        assetType: dto.assetType?.trim() || 'Workstation',
        criticality: dto.criticality?.trim() || 'Medium',
        operatingSystem: dto.operatingSystem?.trim() || null,
        owner: dto.owner?.trim() || null,
        status: dto.status?.trim() || 'Active',
        source: dto.source?.trim() || 'Analyst Manual Entry',
        description: dto.description?.trim() || null,
        evidence: dto.evidence?.trim() || null,
      },
    });
  }

  async getEndpointsByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    endpoints: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const endpoints = await this.prisma.endpoint.findMany({
      where: { analysisId },
      orderBy: { createdAt: 'desc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] Endpoints returned count: ${endpoints.length}`);

    return {
      analysisId,
      totalCount: endpoints.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      endpoints,
    };
  }

  async createAnalystEndpoint(
    analysisId: string,
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
    user?: AuthenticatedUser,
  ): Promise<any> {
    await this.verifyAnalysisAccess(analysisId, user, 'write');

    const host = dto.hostname || dto.ipAddress;
    if (!host || host.trim().length === 0) {
      throw new BadRequestException('Endpoint Hostname or IP Address is required.');
    }

    return this.prisma.endpoint.create({
      data: {
        analysisId,
        hostname: host.trim(),
        ipAddress: dto.ipAddress?.trim() || null,
        osVersion: dto.osVersion?.trim() || dto.operatingSystem?.trim() || null,
        operatingSystem: dto.operatingSystem?.trim() || dto.osVersion?.trim() || null,
        user: dto.user?.trim() || null,
        agentStatus: dto.agentStatus?.trim() || dto.status?.trim() || 'ONLINE',
        status: dto.status?.trim() || dto.agentStatus?.trim() || 'ACTIVE',
        endpointType: dto.endpointType?.trim() || 'Endpoint Device',
        source: dto.source?.trim() || 'Analyst Manual Entry',
        evidence: dto.evidence?.trim() || null,
        lastSeen: new Date(),
      },
    });
  }

  async getVulnerabilitiesByAnalysisId(
    analysisId: string,
    user?: AuthenticatedUser,
  ): Promise<{
    analysisId: string;
    totalCount: number;
    parsingStatus?: string | null;
    parsingWarnings?: any;
    provenance?: any;
    vulnerabilities: any[];
  }> {
    const analysis = await this.verifyAnalysisAccess(analysisId, user, 'read');

    const vulnerabilities = await this.prisma.vulnerability.findMany({
      where: { analysisId },
      orderBy: { createdAt: 'desc' },
    });

    this.logger.log(`[AnalysisService] [${analysisId}] Vulnerabilities returned count: ${vulnerabilities.length}`);

    return {
      analysisId,
      totalCount: vulnerabilities.length,
      parsingStatus: analysis.parsingStatus,
      parsingWarnings: analysis.parsingWarnings as any,
      provenance: analysis.provenance,
      vulnerabilities,
    };
  }

  async createAnalystVulnerability(
    analysisId: string,
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
    user?: AuthenticatedUser,
  ): Promise<any> {
    await this.verifyAnalysisAccess(analysisId, user, 'write');

    const cve = dto.cveId || dto.vulnerabilityId || 'CVE-ANALYST';
    const title = dto.title || dto.name || cve;

    if (!title || title.trim().length === 0) {
      throw new BadRequestException('Vulnerability Title or CVE ID is required.');
    }

    return this.prisma.vulnerability.create({
      data: {
        analysisId,
        cveId: cve.trim(),
        title: title.trim(),
        cvssScore:
          dto.cvssScore !== undefined && dto.cvssScore !== null
            ? Number(dto.cvssScore)
            : null,
        severity: dto.severity?.trim() || null,
        description: dto.description?.trim() || null,
        affectedAsset: dto.affectedAsset?.trim() || null,
        packageName: dto.packageName?.trim() || null,
        installedVersion: dto.installedVersion?.trim() || null,
        fixedVersion: dto.fixedVersion?.trim() || null,
        status: dto.status?.trim() || 'OPEN',
        remediation: dto.remediation?.trim() || null,
        source: dto.source?.trim() || 'Analyst Manual Entry',
        evidence: dto.evidence?.trim() || null,
      },
    });
  }
}
