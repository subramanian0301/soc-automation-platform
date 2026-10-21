import { Injectable, BadRequestException } from '@nestjs/common';
import { IFileParser, FileParserOptions } from './interfaces/parser.interface';
import { JsonParser } from './parsers/json.parser';
import { CsvParser } from './parsers/csv.parser';
import { TextLogParser } from './parsers/text-log.parser';
import { AnalysisInput } from './interfaces/analysis-input.interface';

@Injectable()
export class ParserService {
  constructor(
    private readonly jsonParser: JsonParser,
    private readonly csvParser: CsvParser,
    private readonly textLogParser: TextLogParser,
  ) {}

  async parseFile(
    content: string,
    options: FileParserOptions,
  ): Promise<{ format: string; analysisInput: AnalysisInput }> {
    const ext = options.extension.toLowerCase();
    let selectedParser: IFileParser;
    let detectedFormat = 'TXT';

    // Priority 1: Check if content is valid JSON regardless of extension
    if (this.jsonParser.canParse(ext, options.mimeType, content)) {
      selectedParser = this.jsonParser;
      detectedFormat = 'JSON';
    } else if (ext === '.csv' || options.mimeType.includes('csv') || this.csvParser.canParse(ext, options.mimeType)) {
      selectedParser = this.csvParser;
      detectedFormat = 'CSV';
    } else {
      selectedParser = this.textLogParser;
      detectedFormat = ext === '.log' ? 'LOG' : 'TXT';
    }

    const analysisInput = await selectedParser.parse(content, options);
    return {
      format: detectedFormat,
      analysisInput,
    };
  }
}
