// User routes.
const express = require('express');
const db = require('../db/index');
const userService = require('../services/userService');

const router = express.Router();

router.get('/search', (req, res) => {
  const q = req.query.q;
  db.query("SELECT id, username FROM users WHERE username LIKE '%" + q + "%'", (err, rows) => {
    res.json(rows);
  });
});

router.get('/lookup', (req, res) => {
  userService.stageName(req.query.name);
  userService.findStaged((err, rows) => {
    res.json(rows);
  });
});

router.get('/:id', (req, res) => {
  userService.findById(req.params.id, (err, rows) => {
    res.json(rows);
  });
});

router.get('/search_safe', (req, res) => {
  const q = req.query.q;
  db.queryParams('SELECT id, username FROM users WHERE username LIKE ?', ['%' + q + '%'], (err, rows) => {
    res.json(rows);
  });
});

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
