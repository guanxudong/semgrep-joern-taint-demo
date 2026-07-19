// File retrieval logic.
import * as fs from 'fs';
import * as path from 'path';

const UPLOAD_DIR = '/var/www/uploads';
const ALLOWED = new Set(['readme.txt', 'help.txt']);

// Passes user-controlled name into a filesystem path (sink).
export function readUserFile(name: string): string {
  const p = path.join(UPLOAD_DIR, name);
  return fs.readFileSync(p, 'utf-8');
}

export function readWhitelisted(name: string): string {
  if (!ALLOWED.has(name)) {
    throw new Error('file not allowed');
  }
  return fs.readFileSync(path.join(UPLOAD_DIR, name), 'utf-8');
}
