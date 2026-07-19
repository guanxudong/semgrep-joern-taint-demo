// Admin routes: no authorization at all.
import { Router, Request, Response } from 'express';

const db = require('../db/index');

const router = Router();

// VULN: js-broken-access-control-01 (broken-access-control, cwe-862)
router.get('/users', (req: Request, res: Response) => {
  db.query('SELECT id, username, email, role FROM users', (err: unknown, rows: unknown) => {
    res.json(rows);
  });
});

// VULN: js-broken-access-control-01 (broken-access-control, cwe-862)
router.delete('/users/:id', (req: Request, res: Response) => {
  db.query('DELETE FROM users WHERE id = ' + req.params.id, () => {
    res.json({ deleted: req.params.id });
  });
});

export default router;
