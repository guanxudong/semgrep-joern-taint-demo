// Admin routes.
import { Router, Request, Response } from 'express';

const db = require('../db/index');

const router = Router();

router.get('/users', (req: Request, res: Response) => {
  db.query('SELECT id, username, email, role FROM users', (err: unknown, rows: unknown) => {
    res.json(rows);
  });
});

router.delete('/users/:id', (req: Request, res: Response) => {
  db.query('DELETE FROM users WHERE id = ' + req.params.id, () => {
    res.json({ deleted: req.params.id });
  });
});

export default router;
