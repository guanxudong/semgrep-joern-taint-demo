// XML ingestion routes.
import { Router, Request, Response } from 'express';

const libxmljs = require('libxmljs');

const router = Router();

router.post('/parse', (req: Request, res: Response) => {
  const xml = String(req.body);
  const doc = libxmljs.parseXml(xml, { noent: true, noclean: true });
  res.json({ root: doc.root().name(), text: doc.root().text() });
});

router.post('/parse_safe', (req: Request, res: Response) => {
  const xml = String(req.body);
  const doc = libxmljs.parseXml(xml, { noent: false });
  res.json({ root: doc.root().name(), text: doc.root().text() });
});

export default router;
