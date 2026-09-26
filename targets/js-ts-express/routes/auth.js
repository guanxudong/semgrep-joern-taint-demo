// Auth routes.
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config');

const router = express.Router();

router.post('/login', (req, res) => {
  const username = req.body.username;
  const token = jwt.sign({ sub: username, role: 'user' }, config.JWT_SECRET);
  res.json({ token });
});

router.post('/reset', (req, res) => {
  const username = req.body.username;
  const token = crypto.createHash('md5').update(String(username)).digest('hex').slice(0, 8);
  res.json({ reset_token: token });
});

module.exports = router;
