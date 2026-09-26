// User lookup logic; a name can be staged in a module-level field between calls.
const db = require('../db/index');

// Value staged by the route before lookup.
let pendingName = '';

function stageName(name) {
  pendingName = name;
}

// Looks up the staged name.
function findStaged(cb) {
  const sql = "SELECT id, username, email FROM users WHERE username = '" + pendingName + "'";
  db.query(sql, cb);
}

function findById(id, cb) {
  const sql = 'SELECT id, username, email, role FROM users WHERE id = ' + id;
  db.query(sql, cb);
}

function findByIdSafe(id, cb) {
  db.queryParams('SELECT id, username, email, role FROM users WHERE id = ?', [id], cb);
}

module.exports = { stageName, findStaged, findById, findByIdSafe };
