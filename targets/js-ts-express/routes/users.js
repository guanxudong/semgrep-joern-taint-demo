// User routes: SQL injection (shallow + deep), IDOR, plus safe counter-examples.
const express = require('express');
const db = require('../db/index');
const userService = require('../services/userService');

const router = express.Router();

// VULN: js-sqli-01 (sqli, cwe-89) [shallow]
router.get('/search', (req, res) => {
  const q = req.query.q;
  db.query("SELECT id, username FROM users WHERE username LIKE '%" + q + "%'", (err, rows) => {
    res.json(rows);
  });
});

// VULN: js-sqli-02 (sqli, cwe-89) [deep, taint via module field]
router.get('/lookup', (req, res) => {
  userService.stageName(req.query.name);
  userService.findStaged((err, rows) => {
    res.json(rows);
  });
});

// VULN: js-idor-01 (idor, cwe-639)
router.get('/:id', (req, res) => {
  userService.findById(req.params.id, (err, rows) => {
    res.json(rows);
  });
});

// SAFE: js-safe-01 (mimics sqli) - parameterized query
router.get('/search_safe', (req, res) => {
  const q = req.query.q;
  db.queryParams('SELECT id, username FROM users WHERE username LIKE ?', ['%' + q + '%'], (err, rows) => {
    res.json(rows);
  });
});

// SAFE: js-safe-02 (mimics idor) - ownership checked against caller identity
router.get('/me/:id', (req, res) => {
  const sessionUser = req.headers['x-user-id'];
  if (sessionUser !== req.params.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  userService.findByIdSafe(req.params.id, (err, rows) => {
    res.json(rows);
  });
});

module.exports = router;
