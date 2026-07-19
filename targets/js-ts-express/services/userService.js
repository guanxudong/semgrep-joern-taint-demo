// User lookup logic; holds tainted input in a module-level field between calls.
const db = require('../db/index');

// Tainted value staged by the route (taint via module field).
let pendingName = '';

function stageName(name) {
  pendingName = name;
}

// Reads the staged field and reaches the sink (deep chain end).
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
