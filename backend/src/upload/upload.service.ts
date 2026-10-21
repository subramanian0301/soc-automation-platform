import { Injectable, BadRequestException } from '@nestjs/common';
import * as path from 'path';
import * as fs from 'fs';
import { randomUUID } from 'crypto';

export interface StoredFileDetails {
  storedPath: string;
  storageKey: string;
  storedFileName: string;
  originalFileName: string;
  fileSize: number;
  mimeType: string;
  extension: string;
}

@Injectable()
export class UploadService {
  private readonly uploadDir: string;
  private readonly allowedExtensions = new Set(['.log', '.txt', '.json', '.csv', '.ndjson', '.jsonl']);
  private readonly maxFileSize = 50 * 1024 * 1024; // 50MB limit

  constructor() {
    // Stored in root uploads folder d:\soc 2.0\uploads
    this.uploadDir = path.resolve(process.cwd(), '../uploads');
    if (!fs.existsSync(this.uploadDir)) {
      // Fallback if current working directory is backend
      const altDir = path.resolve(process.cwd(), 'uploads');
      if (fs.existsSync(altDir)) {
        this.uploadDir = altDir;
      } else {
        fs.mkdirSync(this.uploadDir, { recursive: true });
      }
    }
  }
  validateFile(file: Express.Multer.File): { extension: string; sanitizedOriginalName: string } {
    if (!file || !file.buffer) {
      throw new BadRequestException('No file provided in upload request.');
    }

    if (file.size > this.maxFileSize || (file.buffer && file.buffer.length > this.maxFileSize)) {
      throw new BadRequestException(`File size exceeds maximum allowed limit of ${this.maxFileSize / (1024 * 1024)}MB.`);
    }

    // Path traversal prevention: strip any path directories from original name
    const rawName = path.basename(file.originalname || 'unknown');
    const sanitizedOriginalName = rawName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const extension = path.extname(sanitizedOriginalName).toLowerCase();

    if (!extension || !this.allowedExtensions.has(extension)) {
      throw new BadRequestException(
        `Unsupported file type '${extension || 'unknown'}'. Allowed extensions: .log, .txt, .json, .csv, .ndjson, .jsonl`,
      );
    }

    if ((!file.buffer || file.buffer.length === 0) && (extension === '.json' || extension === '.ndjson' || extension === '.jsonl')) {
      throw new BadRequestException('Uploaded file is empty (0 bytes).');
    }

    // Binary null byte check (prevents binaries/PE executables disguised as text logs)
    if (file.buffer.includes(0x00)) {
      throw new BadRequestException('Invalid file encoding: Uploaded file contains binary data and cannot be parsed as text.');
    }

    // Strict UTF-8 validation
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      decoder.decode(file.buffer);
    } catch {
      throw new BadRequestException('Invalid file encoding: Uploaded file must be valid UTF-8 text.');
    }

    return { extension, sanitizedOriginalName };
  }

  async saveFile(file: Express.Multer.File, analysisId: string): Promise<StoredFileDetails> {
    const { extension, sanitizedOriginalName } = this.validateFile(file);

    const safeStorageKey = `${analysisId}_${Date.now()}`;
    const storedFileName = `${safeStorageKey}_${sanitizedOriginalName}`;
    const storedPath = path.join(this.uploadDir, storedFileName);

    // Save file buffer safely
    await fs.promises.writeFile(storedPath, file.buffer);

    return {
      storedPath,
      storageKey: safeStorageKey,
      storedFileName,
      originalFileName: sanitizedOriginalName,
      fileSize: file.size,
      mimeType: file.mimetype || 'application/octet-stream',
      extension,
    };
  }

  async removeFile(filePath: string): Promise<void> {
    try {
      if (fs.existsSync(filePath)) {
        await fs.promises.unlink(filePath);
      }
    } catch (e) {
      console.error(`Failed to clean up file at ${filePath}:`, e);
    }
  }
}
