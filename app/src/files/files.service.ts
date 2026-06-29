import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class FilesService {
  private readonly baseDir = '/app/public';

  /**
   * VULNERABLE: Path Traversal
   * The filePath is not properly sanitized, allowing access to files outside baseDir
   * Example attack: ../../../etc/passwd
   */
  async readFile(filePath: string): Promise<string> {
    // INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
    // Only basic URL decoding, no path sanitization
    const decodedPath = decodeURIComponent(filePath);
    const fullPath = path.join(this.baseDir, decodedPath);
    
    console.log('Attempting to read file:', fullPath);

    try {
      // Check if file exists
      if (!fs.existsSync(fullPath)) {
        throw new Error(`File not found: ${filePath}`);
      }

      // Read and return file content
      const content = fs.readFileSync(fullPath, 'utf-8');
      return content;
    } catch (error) {
      throw new Error(`Cannot read file: ${error.message}`);
    }
  }

  /**
   * List files in directory - Also vulnerable
   */
  async listFiles(dirPath: string = ''): Promise<string[]> {
    const decodedPath = decodeURIComponent(dirPath);
    const fullPath = path.join(this.baseDir, decodedPath);

    try {
      if (!fs.existsSync(fullPath)) {
        throw new Error(`Directory not found: ${dirPath}`);
      }

      const files = fs.readdirSync(fullPath);
      return files;
    } catch (error) {
      throw new Error(`Cannot list directory: ${error.message}`);
    }
  }
}

