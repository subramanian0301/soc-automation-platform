import { AnalysisInput } from './analysis-input.interface';

export interface FileParserOptions {
  originalFileName: string;
  fileSize: number;
  mimeType: string;
  extension: string;
  calculatedHashes?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

export interface IFileParser {
  canParse(extension: string, mimeType: string, content: string): boolean;
  parse(content: string, options: FileParserOptions): Promise<AnalysisInput> | AnalysisInput;
}
