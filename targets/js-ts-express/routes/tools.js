// Diagnostic tool routes: command injection (shallow + deep) and RCE.
const express = require('express');
const { exec } = require('child_process');
const { toolService } = require('../services/toolService');

const router = express.Router();

// VULN: js-cmdi-01 (cmdi, cwe-78) [shallow]
router.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    res.json({ out: stdout });
  });
});

// VULN: js-cmdi-02 (cmdi, cwe-78) [deep, taint via instance field]
router.get('/diagnose', (req, res) => {
  toolService.stageTarget(req.query.host);
  toolService.runStagedDiag((err, out) => {
    res.json({ out });
  });
});

// VULN: js-rce-01 (rce, cwe-94) [shallow]
router.post('/calc', (req, res) => {
  const expr = req.body.expr;
  const result = eval(expr);
  res.json({ result });
});

module.exports = router;
