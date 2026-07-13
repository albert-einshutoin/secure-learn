import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class FilesService {
  private readonly baseDir: string;

  constructor(@Optional() @Inject('PUBLIC_DIR') baseDir = process.env.PUBLIC_DIR || '/app/public') {
    this.baseDir = path.resolve(baseDir);
  }

  async readFile(filePath: string): Promise<string> {
    const fullPath = this.resolveInsideBaseDir(filePath);

    if (!fs.existsSync(fullPath)) {
      throw new NotFoundException('File not found');
    }

    const stat = fs.statSync(fullPath);
    if (!stat.isFile()) {
      throw new BadRequestException('Path is not a file');
    }

    return fs.readFileSync(fullPath, 'utf-8');
  }

  async listFiles(dirPath: string = ''): Promise<string[]> {
    const fullPath = this.resolveInsideBaseDir(dirPath, true);

    if (!fs.existsSync(fullPath)) {
      throw new NotFoundException('Directory not found');
    }

    const stat = fs.statSync(fullPath);
    if (!stat.isDirectory()) {
      throw new BadRequestException('Path is not a directory');
    }

    return fs.readdirSync(fullPath).sort();
  }

  private resolveInsideBaseDir(inputPath: string, allowBaseDir = false): string {
    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(String(inputPath || ''));
    } catch {
      throw new BadRequestException('Invalid path encoding');
    }

    // An empty path is meaningful only for directory listing: it represents
    // the public root. File reads still reject it to avoid ambiguous behavior.
    if ((!decodedPath && !allowBaseDir) || decodedPath.includes('\0')) {
      throw new BadRequestException('Invalid file path');
    }

    const relativeInput = decodedPath.replace(/^[/\\]+/, '');
    const fullPath = path.resolve(this.baseDir, relativeInput);
    const relativeToBase = path.relative(this.baseDir, fullPath);

    // path.resolve alone normalizes traversal; the relative check proves the final target
    // still lives under the published directory instead of trusting the input string.
    if (relativeToBase === '..' || relativeToBase.startsWith(`..${path.sep}`) || path.isAbsolute(relativeToBase)) {
      throw new ForbiddenException('Path traversal denied');
    }

    return fullPath;
  }
}

