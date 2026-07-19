# Ground Truth — js-ts-express

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through a module/instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.
Express route handlers are anonymous; "Entrypoint fn" names the semantic handler.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| js-sqli-01 | vuln | A | sqli | 89 | shallow | GET /users/search | search | db/index.js query (`pool.query`) | users.js → db/index.js |
| js-sqli-02 | vuln | A | sqli | 89 | deep | GET /users/lookup | lookup | db/index.js query (`pool.query`) | users.js → userService.js (field `pendingName`) → db/index.js |
| js-xss-01 | vuln | A | xss | 79 | shallow | GET /render/hello | hello | render.js hello (`res.send`) | render.js |
| js-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools/ping | ping | tools.js ping (`exec`) | tools.js |
| js-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools/diagnose | diagnose | toolService.ts runStagedDiag (`exec`) | tools.js → toolService.ts (field `target`) |
| js-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /files/download | download | fileService.ts readUserFile (`fs.readFileSync`) | files.ts → fileService.ts |
| js-rce-01 | vuln | A | rce | 94 | shallow | POST /tools/calc | calc | tools.js calc (`eval`) | tools.js |
| js-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml/parse | parse | xml.ts parse (`parseXml` noent) | xml.ts |
| js-deserialization-01 | vuln | A | deserialization | 502 | medium | POST /profile/import | import | profile.js import (`unserialize`) | profile.js |
| js-ssti-01 | vuln | A | ssti | 1336 | medium | POST /render/preview | preview | render.js preview (`ejs.render`) | render.js |
| js-idor-01 | vuln | B | idor | 639 | medium | GET /users/:id | getUser | — | users.js → userService.js |
| js-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /orders/transfer | transfer | — | orders.ts → orderService.ts |
| js-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /orders/withdraw | withdraw | — | orders.ts → orderService.ts |
| js-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile/update | update | — | profile.js |
| js-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile/update | update | — | profile.js |
| js-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin/users | listUsers | — | admin.ts → db/index.js |
| js-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth/login | login | — | auth.js → config.js |
| js-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /users/search_safe | searchSafe | parameterized query | users.js → db/index.js |
| js-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /users/me/:id | getOwnProfile | ownership checked | users.js → userService.js |
| js-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml/parse_safe | parseSafe | noent: false | xml.ts |
| js-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /files/download_safe | downloadSafe | allow-list check | files.ts → fileService.ts |
| js-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /orders/withdraw_safe | withdrawSafe | mutex flag | orders.ts → orderService.ts |

Notes:
- js-priv-esc-01 and js-mass-assignment-01 share the same endpoint on purpose
  (one flawed handler exhibiting two B-class weaknesses).
- js-auth-flaws-01 also covers `/auth/reset` (predictable md5(username) token).
- js-business-logic-01 also covers `/orders/coupon` (unlimited coupon reuse).
- js-broken-access-control-01 also covers `DELETE /admin/users/:id`.
- JavaScript and TypeScript are intentionally mixed in one project; filter by
  file extension if you need per-language scoring.
