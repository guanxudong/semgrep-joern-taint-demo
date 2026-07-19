// Rendering routes: SSTI and reflected XSS.
const express = require('express');
const ejs = require('ejs');

const router = express.Router();

// VULN: js-ssti-01 (ssti, cwe-1336) [medium]
router.post('/preview', (req, res) => {
  const tpl = req.body.template;
  const html = ejs.render(tpl, { user: req.body.user });
  res.send(html);
});

// VULN: js-xss-01 (xss, cwe-79) [shallow]
router.get('/hello', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

module.exports = router;
