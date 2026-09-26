// Rendering routes.
const express = require('express');
const ejs = require('ejs');

const router = express.Router();

router.post('/preview', (req, res) => {
  const tpl = req.body.template;
  const html = ejs.render(tpl, { user: req.body.user });
  res.send(html);
});

router.get('/hello', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

module.exports = router;
