// Profile routes: mass assignment, privilege escalation, unsafe deserialization.
const express = require('express');
const serialize = require('node-serialize');

const router = express.Router();

const USERS = { alice: { username: 'alice', email: '', role: 'user' } };

// VULN: js-mass-assignment-01 (mass-assignment, cwe-915)
// VULN: js-priv-esc-01 (priv-esc, cwe-269) - role accepted from body and persisted
router.post('/update', (req, res) => {
  const username = req.body.username;
  const user = USERS[username] || { username, email: '', role: 'user' };
  Object.assign(user, req.body);
  USERS[username] = user;
  res.json(user);
});

// VULN: js-deserialization-01 (deserialization, cwe-502) [medium]
router.post('/import', (req, res) => {
  const data = req.body.data;
  const user = serialize.unserialize(data);
  USERS[user.username] = user;
  res.json({ imported: user.username });
});

module.exports = router;
