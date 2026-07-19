// Raw mysql data-access helpers. query() is the SQLi sink.
const mysql = require('mysql2');
const config = require('../config');

const pool = mysql.createPool({
  host: config.DB_HOST,
  user: config.DB_USER,
  password: config.DB_PASSWORD,
  database: config.DB_NAME,
});

function query(sql, cb) {
  pool.query(sql, cb);
}

function queryParams(sql, args, cb) {
  pool.query(sql, args, cb);
}

module.exports = { query, queryParams };
