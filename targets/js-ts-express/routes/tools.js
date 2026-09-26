// Diagnostic tool routes.
const express = require('express');
const { exec } = require('child_process');
const { toolService } = require('../services/toolService');

const router = express.Router();

router.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    res.json({ out: stdout });
  });
});

router.get('/diagnose', (req, res) => {
  toolService.stageTarget(req.query.host);
  toolService.runStagedDiag((err, out) => {
    res.json({ out });
  });
});

router.post('/calc', (req, res) => {
  const expr = req.body.expr;
  const result = eval(expr);
  res.json({ result });
});

module.exports = router;
