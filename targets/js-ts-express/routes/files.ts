// File download routes.
import { Router, Request, Response } from 'express';
import { readUserFile, readWhitelisted } from '../services/fileService';

const router = Router();

router.get('/download', (req: Request, res: Response) => {
  const name = String(req.query.name ?? '');
  res.json({ content: readUserFile(name) });
});

router.get('/download_safe', (req: Request, res: Response) => {
  const name = String(req.query.name ?? '');
  try {
    res.json({ content: readWhitelisted(name) });
  } catch {
    res.status(400).json({ error: 'file not allowed' });
  }
});

export default router;
