// Profile routes.
const express = require('express');
const serialize = require('node-serialize');

const router = express.Router();

const USERS = { alice: { username: 'alice', email: '', role: 'user' } };

router.post('/update', (req, res) => {
  const username = req.body.username;
  const user = USERS[username] || { username, email: '', role: 'user' };
  Object.assign(user, req.body);
  USERS[username] = user;
  res.json(user);
});

router.post('/import', (req, res) => {
  const data = req.body.data;
  const user = serialize.unserialize(data);
  USERS[user.username] = user;
  res.json({ imported: user.username });
});

module.exports = router;
