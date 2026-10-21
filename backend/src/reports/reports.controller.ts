import {
  Controller,
  Get,
  Param,
  Query,
  Res,
  Request,
  BadRequestException,
} from '@nestjs/common';
import { Response } from 'express';
import { ReportsService } from './reports.service';

@Controller()
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Get('analyses/:analysisId/reports/:reportType')
  async getAnalysisReport(
    @Param('analysisId') analysisId: string,
    @Param('reportType') reportType: string,
    @Request() req: any,
  ) {
    return this.reportsService.getAnalysisReportData(
      analysisId,
      reportType,
      req.user,
    );
  }

  @Get('analyses/:analysisId/reports/:reportType/export')
  async exportReport(
    @Param('analysisId') analysisId: string,
    @Param('reportType') reportType: string,
    @Query('format') format: string,
    @Request() req: any,
    @Res() res: Response,
  ) {
    const fmt = (format || 'pdf').toLowerCase();
    const safeType = reportType.replace(/[^a-zA-Z0-9_-]/g, '');
    const safeId = analysisId.replace(/[^a-zA-Z0-9_-]/g, '');

    if (fmt === 'pdf') {
      const pdfBuffer = await this.reportsService.exportPdfReport(
        analysisId,
        reportType,
        req.user,
      );
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="report_${safeType}_${safeId}.pdf"`,
      );
      return res.send(pdfBuffer);
    } else if (fmt === 'csv') {
      const csvData = await this.reportsService.exportCsvReport(
        analysisId,
        reportType,
        req.user,
      );
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="report_${safeType}_${safeId}.csv"`,
      );
      return res.send(csvData);
    } else {
      throw new BadRequestException(
        `Unsupported export format '${format}'. Supported formats: pdf, csv.`,
      );
    }
  }

  @Get('analytics/enterprise')
  async getEnterpriseAnalytics(@Request() req: any) {
    return this.reportsService.getEnterpriseAnalytics(req.user);
  }
}
