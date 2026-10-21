import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as PDFDocument from 'pdfkit';

export type ReportType =
  | 'analysis-summary'
  | 'security-findings'
  | 'incidents-cases'
  | 'assets-endpoints'
  | 'vulnerabilities'
  | 'soar-activity';

export interface AuthenticatedUser {
  id: string;
  sub?: string;
  username: string;
  email?: string;
  role: string;
}

@Injectable()
export class ReportsService {
  constructor(private readonly prisma: PrismaService) {}

  async getAnalysisReportData(
    analysisId: string,
    reportType: string,
    user?: AuthenticatedUser,
  ): Promise<any> {
    const analysis = await this.prisma.analysis.findUnique({
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
      },
    });

    if (!analysis) {
      throw new NotFoundException(`Analysis with ID '${analysisId}' not found.`);
    }

    if (user && analysis.userId && user.role !== 'ADMIN' && analysis.userId !== user.id) {
      throw new ForbiddenException(
        `Access denied: You do not have permission to access reports for analysis '${analysisId}'.`,
      );
    }

    const type = reportType.toLowerCase();
    const generatedAt = new Date().toISOString();

    switch (type) {
      case 'analysis-summary':
        return {
          reportType: 'analysis-summary',
          analysisId,
          generatedAt,
          metadata: {
            fileName: analysis.fileName,
            originalFileName: analysis.originalFileName,
            fileSize: analysis.fileSize,
            fileType: analysis.fileType,
            mimeType: analysis.mimeType,
            uploadedAt: analysis.uploadedAt,
            hostname: analysis.hostname,
            username: analysis.username,
            operatingSystem: analysis.operatingSystem,
          },
          risk: {
            riskScore: analysis.riskScore,
            threatLevel: analysis.threatLevel,
            recommendation: analysis.recommendation,
          },
          hashes: analysis.hashes,
          fileProperties: analysis.fileProperties,
        };

      case 'security-findings':
        return {
          reportType: 'security-findings',
          analysisId,
          generatedAt,
          riskScore: analysis.riskScore,
          threatLevel: analysis.threatLevel,
          yaraResults: analysis.yaraResults || [],
          virusTotalResult: analysis.virusTotalResult || null,
          iocs: analysis.iocs || [],
          mitreTechniques: analysis.mitreTechniques || [],
          behaviorEvents: analysis.behaviorEvents || [],
          sandboxResults: analysis.sandboxResults || [],
          siemEventsCount: analysis.siemEvents?.length || 0,
        };

      case 'incidents-cases':
        return {
          reportType: 'incidents-cases',
          analysisId,
          generatedAt,
          incidentsCount: analysis.incidents.length,
          incidents: analysis.incidents,
          casesCount: analysis.cases.length,
          cases: analysis.cases,
        };

      case 'assets-endpoints':
        return {
          reportType: 'assets-endpoints',
          analysisId,
          generatedAt,
          assetsCount: analysis.assets.length,
          assets: analysis.assets,
          endpointsCount: analysis.endpoints.length,
          endpoints: analysis.endpoints,
        };

      case 'vulnerabilities':
        return {
          reportType: 'vulnerabilities',
          analysisId,
          generatedAt,
          vulnerabilitiesCount: analysis.vulnerabilities.length,
          vulnerabilities: analysis.vulnerabilities,
        };

      case 'soar-activity':
        return {
          reportType: 'soar-activity',
          analysisId,
          generatedAt,
          soarExecutionsCount: analysis.soarExecutions.length,
          soarExecutions: analysis.soarExecutions.map((s) => ({
            ...s,
            isSimulation: s.status === 'SIMULATION',
          })),
        };

      default:
        throw new BadRequestException(
          `Unsupported report type '${reportType}'. Supported types: analysis-summary, security-findings, incidents-cases, assets-endpoints, vulnerabilities, soar-activity.`,
        );
    }
  }

  async exportCsvReport(
    analysisId: string,
    reportType: string,
    user?: AuthenticatedUser,
  ): Promise<string> {
    const data = await this.getAnalysisReportData(analysisId, reportType, user);
    const escapeCsv = (val: any): string => {
      if (val === null || val === undefined) return 'Not Available';
      let str = String(val);
      if (/^[=+\-@\t\r]/.test(str)) {
        str = "'" + str;
      }
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const lines: string[] = [];

    if (reportType === 'analysis-summary') {
      lines.push('Property,Value');
      lines.push(`Report Type,${escapeCsv(data.reportType)}`);
      lines.push(`Analysis ID,${escapeCsv(data.analysisId)}`);
      lines.push(`Generated At,${escapeCsv(data.generatedAt)}`);
      lines.push(`Original File Name,${escapeCsv(data.metadata.originalFileName)}`);
      lines.push(`File Size (Bytes),${escapeCsv(data.metadata.fileSize)}`);
      lines.push(`File Type,${escapeCsv(data.metadata.fileType)}`);
      lines.push(`Risk Score,${escapeCsv(data.risk.riskScore)}`);
      lines.push(`Threat Level,${escapeCsv(data.risk.threatLevel)}`);
      lines.push(`Hostname,${escapeCsv(data.metadata.hostname)}`);
      lines.push(`Username,${escapeCsv(data.metadata.username)}`);
      lines.push(`OS,${escapeCsv(data.metadata.operatingSystem)}`);
      lines.push(`MD5,${escapeCsv(data.hashes?.md5)}`);
      lines.push(`SHA256,${escapeCsv(data.hashes?.sha256)}`);
    } else if (reportType === 'vulnerabilities') {
      lines.push('CVE ID,Title,CVSS Score,Severity,Status,Affected Asset,Package Name,Remediation');
      if (data.vulnerabilities.length === 0) {
        lines.push('No Vulnerability Data Available,,,,,,,');
      } else {
        for (const v of data.vulnerabilities) {
          lines.push(
            [
              escapeCsv(v.cveId),
              escapeCsv(v.title),
              escapeCsv(v.cvssScore),
              escapeCsv(v.severity),
              escapeCsv(v.status),
              escapeCsv(v.affectedAsset),
              escapeCsv(v.packageName),
              escapeCsv(v.remediation),
            ].join(','),
          );
        }
      }
    } else if (reportType === 'assets-endpoints') {
      lines.push('Category,Identifier,IP Address,Type/OS,Status,Owner/User');
      for (const a of data.assets) {
        lines.push(
          [
            'Asset',
            escapeCsv(a.assetName),
            escapeCsv(a.ipAddress),
            escapeCsv(a.assetType),
            escapeCsv(a.status),
            escapeCsv(a.owner),
          ].join(','),
        );
      }
      for (const e of data.endpoints) {
        lines.push(
          [
            'Endpoint',
            escapeCsv(e.hostname),
            escapeCsv(e.ipAddress),
            escapeCsv(e.osVersion),
            escapeCsv(e.agentStatus),
            escapeCsv(e.user),
          ].join(','),
        );
      }
      if (data.assets.length === 0 && data.endpoints.length === 0) {
        lines.push('No Asset or Endpoint Data Available,,,,,');
      }
    } else if (reportType === 'incidents-cases') {
      lines.push('Entity,ID,Title,Severity/Priority,Status,Reason/Summary');
      for (const inc of data.incidents) {
        lines.push(
          [
            'Incident',
            escapeCsv(inc.id),
            escapeCsv(inc.title),
            escapeCsv(inc.severity),
            escapeCsv(inc.status),
            escapeCsv(inc.reason),
          ].join(','),
        );
      }
      for (const c of data.cases) {
        lines.push(
          [
            'Case',
            escapeCsv(c.caseNumber),
            escapeCsv(c.title),
            escapeCsv(c.priority),
            escapeCsv(c.status),
            escapeCsv(c.summary),
          ].join(','),
        );
      }
    } else if (reportType === 'soar-activity') {
      lines.push('Action Name,Target,Status,Execution Mode,Triggered By,Result');
      if (data.soarExecutions.length === 0) {
        lines.push('No SOAR Data Available,,,,,');
      } else {
        for (const s of data.soarExecutions) {
          lines.push(
            [
              escapeCsv(s.actionName),
              escapeCsv(s.target),
              escapeCsv(s.status),
              s.isSimulation ? 'SIMULATION (Dry Run)' : 'REAL EXECUTION',
              escapeCsv(s.triggeredBy),
              escapeCsv(s.result),
            ].join(','),
          );
        }
      }
    } else {
      lines.push('Report Type,Analysis ID,Generated At');
      lines.push(`${escapeCsv(data.reportType)},${escapeCsv(data.analysisId)},${escapeCsv(data.generatedAt)}`);
    }

    return lines.join('\n');
  }

  async exportPdfReport(
    analysisId: string,
    reportType: string,
    user?: AuthenticatedUser,
  ): Promise<Buffer> {
    const data = await this.getAnalysisReportData(analysisId, reportType, user);

    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ margin: 50 });
        const buffers: Buffer[] = [];

        doc.on('data', (chunk) => buffers.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(buffers)));

        // PDF Header
        doc.fontSize(20).fillColor('#0f172a').text('SOC Security Platform Report', { align: 'center' });
        doc.moveDown(0.5);
        doc
          .fontSize(12)
          .fillColor('#334155')
          .text(`Report Type: ${data.reportType.toUpperCase()}`, { align: 'center' });
        doc.text(`Analysis ID: ${data.analysisId}`, { align: 'center' });
        doc.text(`Generated At: ${data.generatedAt}`, { align: 'center' });
        doc.moveDown(1.5);
        doc.moveTo(50, doc.y).lineTo(550, doc.y).strokeColor('#cbd5e1').stroke();
        doc.moveDown(1.5);

        // Content section
        doc.fontSize(14).fillColor('#1e293b').text('Report Details & Findings', { underline: true });
        doc.moveDown(0.5);

        if (reportType === 'analysis-summary') {
          doc.fontSize(10).fillColor('#334155');
          doc.text(`Original File: ${data.metadata.originalFileName}`);
          doc.text(`File Size: ${data.metadata.fileSize} bytes`);
          doc.text(`File Type: ${data.metadata.fileType}`);
          doc.text(`Risk Score: ${data.risk.riskScore ?? 'Not Available'}`);
          doc.text(`Threat Level: ${data.risk.threatLevel ?? 'Not Available'}`);
          doc.text(`Hostname: ${data.metadata.hostname ?? 'Not Available'}`);
          doc.text(`Username: ${data.metadata.username ?? 'Not Available'}`);
          doc.text(`MD5 Hash: ${data.hashes?.md5 ?? 'Not Available'}`);
          doc.text(`SHA256 Hash: ${data.hashes?.sha256 ?? 'Not Available'}`);
        } else if (reportType === 'vulnerabilities') {
          doc.fontSize(10).fillColor('#334155');
          doc.text(`Total Vulnerabilities: ${data.vulnerabilitiesCount}`);
          doc.moveDown(0.5);
          if (data.vulnerabilities.length === 0) {
            doc.text('No Vulnerability Data Available');
          } else {
            for (const v of data.vulnerabilities) {
              doc.text(`• [${v.cveId}] ${v.title}`);
              doc.text(
                `  Severity: ${v.severity ?? 'Not Available'} | CVSS: ${v.cvssScore ?? 'Not Available'} | Status: ${v.status ?? 'Not Available'}`,
              );
              doc.moveDown(0.3);
            }
          }
        } else if (reportType === 'soar-activity') {
          doc.fontSize(10).fillColor('#334155');
          doc.text(`Total SOAR Executions: ${data.soarExecutionsCount}`);
          doc.moveDown(0.5);
          if (data.soarExecutions.length === 0) {
            doc.text('No SOAR Data Available');
          } else {
            for (const s of data.soarExecutions) {
              doc.text(`• Action: ${s.actionName} [Status: ${s.status}]`);
              doc.text(`  Execution Mode: ${s.isSimulation ? 'SIMULATION (Dry Run)' : 'REAL EXECUTION'}`);
              doc.text(`  Triggered By: ${s.triggeredBy ?? 'Source'}`);
              doc.moveDown(0.3);
            }
          }
        } else {
          doc.fontSize(10).fillColor('#334155');
          doc.text(JSON.stringify(data, null, 2));
        }

        doc.moveDown(2);
        doc
          .fontSize(8)
          .fillColor('#94a3b8')
          .text('Confidential - SOC Platform Generated Report', { align: 'center' });

        doc.end();
      } catch (err) {
        reject(err);
      }
    });
  }

  async getEnterpriseAnalytics(user?: AuthenticatedUser): Promise<any> {
    const isGlobalAdmin = user?.role === 'ADMIN';

    // Scoping analysis queries to authenticated owner unless user is ADMIN
    const analysisWhere: any = { isArchived: false };
    if (!isGlobalAdmin && user?.id) {
      analysisWhere.userId = user.id;
    }

    const childWhere: any = {};
    if (!isGlobalAdmin && user?.id) {
      childWhere.analysis = { userId: user.id };
    }

    const [
      totalAnalyses,
      analyses,
      totalIncidents,
      totalCases,
      totalVulnerabilities,
      vulnerabilities,
      totalAssets,
      totalEndpoints,
      soarExecutions,
    ] = await Promise.all([
      this.prisma.analysis.count({ where: analysisWhere }),
      this.prisma.analysis.findMany({
        where: analysisWhere,
        select: { riskScore: true, threatLevel: true, uploadedAt: true },
      }),
      this.prisma.incident.count({ where: childWhere }),
      this.prisma.case.count({ where: childWhere }),
      this.prisma.vulnerability.count({ where: childWhere }),
      this.prisma.vulnerability.findMany({
        where: childWhere,
        select: { severity: true },
      }),
      this.prisma.asset.count({ where: childWhere }),
      this.prisma.endpoint.count({ where: childWhere }),
      this.prisma.soarExecution.findMany({
        where: childWhere,
        select: { status: true },
      }),
    ]);

    // Risk score distribution
    let lowRisk = 0,
      mediumRisk = 0,
      highRisk = 0,
      criticalRisk = 0,
      missingRisk = 0;
    let lowThreat = 0,
      mediumThreat = 0,
      highThreat = 0,
      criticalThreat = 0,
      missingThreat = 0;

    for (const a of analyses) {
      if (a.riskScore === null || a.riskScore === undefined) {
        missingRisk++;
      } else if (a.riskScore <= 20) {
        lowRisk++;
      } else if (a.riskScore <= 50) {
        mediumRisk++;
      } else if (a.riskScore <= 85) {
        highRisk++;
      } else {
        criticalRisk++;
      }

      if (!a.threatLevel) {
        missingThreat++;
      } else if (a.threatLevel === 'LOW') lowThreat++;
      else if (a.threatLevel === 'MEDIUM') mediumThreat++;
      else if (a.threatLevel === 'HIGH') highThreat++;
      else if (a.threatLevel === 'CRITICAL') criticalThreat++;
    }

    // Vulnerabilities by severity
    const vulnSeverityMap: Record<string, number> = {};
    for (const v of vulnerabilities) {
      const sev = v.severity ? v.severity.toUpperCase() : 'NOT_AVAILABLE';
      vulnSeverityMap[sev] = (vulnSeverityMap[sev] || 0) + 1;
    }

    // SOAR Executions by status
    let soarSimulations = 0;
    let soarCompleted = 0;
    let soarPending = 0;

    for (const s of soarExecutions) {
      if (s.status === 'SIMULATION') soarSimulations++;
      else if (s.status === 'COMPLETED') soarCompleted++;
      else soarPending++;
    }

    return {
      scope: isGlobalAdmin
        ? 'Enterprise-Wide Historical Records'
        : `User-Scoped Analytics (${user?.username || 'Current User'})`,
      isGlobalAdmin,
      generatedAt: new Date().toISOString(),
      totalAnalyses,
      riskScoreDistribution: {
        low: lowRisk,
        medium: mediumRisk,
        high: highRisk,
        critical: criticalRisk,
        missing: missingRisk,
      },
      threatLevelDistribution: {
        LOW: lowThreat,
        MEDIUM: mediumThreat,
        HIGH: highThreat,
        CRITICAL: criticalThreat,
        MISSING: missingThreat,
      },
      counts: {
        incidents: totalIncidents,
        cases: totalCases,
        vulnerabilities: totalVulnerabilities,
        assets: totalAssets,
        endpoints: totalEndpoints,
        soarExecutions: soarExecutions.length,
      },
      vulnerabilitiesBySeverity: vulnSeverityMap,
      soarStatusBreakdown: {
        simulations: soarSimulations,
        completed: soarCompleted,
        other: soarPending,
      },
    };
  }
}
