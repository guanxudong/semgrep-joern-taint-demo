// File download routes: path traversal plus a whitelisted variant.
import { Router, Request, Response } from 'express';
import { readUserFile, readWhitelisted } from '../services/fileService';

const router = Router();

// VULN: js-path-traversal-01 (path-traversal, cwe-22) [medium]
router.get('/download', (req: Request, res: Response) => {
  const name = String(req.query.name ?? '');
  res.json({ content: readUserFile(name) });
});

// SAFE: js-safe-04 (mimics path-traversal) - whitelist validation
router.get('/download_safe', (req: Request, res: Response) => {
  const name = String(req.query.name ?? '');
  try {
    res.json({ content: readWhitelisted(name) });
  } catch {
    res.status(400).json({ error: 'file not allowed' });
  }
});

export default router;
