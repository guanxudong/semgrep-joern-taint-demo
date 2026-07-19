// XML ingestion routes: XXE plus an entity-safe variant.
import { Router, Request, Response } from 'express';

const libxmljs = require('libxmljs');

const router = Router();

// VULN: js-xxe-01 (xxe, cwe-611) [shallow]
router.post('/parse', (req: Request, res: Response) => {
  const xml = String(req.body);
  const doc = libxmljs.parseXml(xml, { noent: true, noclean: true });
  res.json({ root: doc.root().name(), text: doc.root().text() });
});

// SAFE: js-safe-03 (mimics xxe) - entities not expanded
router.post('/parse_safe', (req: Request, res: Response) => {
  const xml = String(req.body);
  const doc = libxmljs.parseXml(xml, { noent: false });
  res.json({ root: doc.root().name(), text: doc.root().text() });
});

export default router;
