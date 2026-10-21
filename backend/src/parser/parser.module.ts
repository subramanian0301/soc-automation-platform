import { Module } from '@nestjs/common';
import { ParserService } from './parser.service';
import { AnalysisNormalizer } from './normalizer/analysis.normalizer';
import { JsonParser } from './parsers/json.parser';
import { CsvParser } from './parsers/csv.parser';
import { TextLogParser } from './parsers/text-log.parser';

@Module({
  providers: [
    AnalysisNormalizer,
    JsonParser,
    CsvParser,
    TextLogParser,
    ParserService,
  ],
  exports: [ParserService, AnalysisNormalizer],
})
export class ParserModule {}
