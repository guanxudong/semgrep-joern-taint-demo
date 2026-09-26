# Ground Truth — php-laravel

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance property.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| php-sqli-01 | vuln | A | sqli | 89 | shallow | GET /users/search | UserController.search | Db.php query (`self::pdo()->query($sql)`) | UserController.php → Db.php |
| php-sqli-02 | vuln | A | sqli | 89 | deep | GET /users/lookup | UserController.lookup | Db.php query (`self::pdo()->query($sql)`) | UserController.php → UserService.php (property `$pendingName`) → Db.php |
| php-xss-01 | vuln | A | xss | 79 | shallow | GET /render/hello | RenderController.hello | RenderController.php hello (HTML concat) | RenderController.php |
| php-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools/ping | ToolController.ping | ToolController.php ping (`system`) | ToolController.php |
| php-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools/diagnose | ToolController.diagnose | ToolService.php runStagedDiag (`shell_exec`) | ToolController.php → ToolService.php (property `$target`) |
| php-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /files/download | FileController.download | FileService.php readUserFile (`file_get_contents`) | FileController.php → FileService.php |
| php-rce-01 | vuln | A | rce | 94 | shallow | POST /tools/calc | ToolController.calc | ToolController.php calc (`eval`) | ToolController.php |
| php-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml/parse | XmlController.parse | XmlController.php parse (`LIBXML_NOENT`) | XmlController.php |
| php-deserialization-01 | vuln | A | deserialization | 502 | shallow | POST /profile/import | ProfileController.import | ProfileController.php import (`unserialize`) | ProfileController.php |
| php-ssti-01 | vuln | A | ssti | 1336 | shallow | GET /render/preview | RenderController.preview | RenderController.php preview (`Blade::render`) | RenderController.php |
| php-idor-01 | vuln | B | idor | 639 | medium | GET /users/{id} | UserController.show | — | UserController.php → UserService.php |
| php-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /orders/transfer | OrderController.transfer | — | OrderController.php → OrderService.php |
| php-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /orders/withdraw | OrderController.withdraw | — | OrderController.php → OrderService.php |
| php-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile/update | ProfileController.update | — | ProfileController.php |
| php-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile/update | ProfileController.update | — | ProfileController.php |
| php-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin/users | AdminController.listUsers | — | AdminController.php → Db.php |
| php-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth/login | AuthController.login | — | AuthController.php → config/app.php |
| php-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /users/v2/search | UserController.searchV2 | parameterized query | UserController.php → Db.php |
| php-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /users/me/{id} | UserController.me | ownership checked | UserController.php → UserService.php |
| php-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml/v2/parse | XmlController.parseV2 | LIBXML_NONET, no LIBXML_NOENT | XmlController.php |
| php-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /files/v2/download | FileController.downloadV2 | allow-list check | FileController.php → FileService.php |
| php-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /orders/v2/withdraw | OrderController.withdrawV2 | flock(LOCK_EX) | OrderController.php → OrderService.php |

Notes:
- php-priv-esc-01 and php-mass-assignment-01 share the same endpoint on purpose
  (one flawed handler exhibiting two B-class weaknesses).
- php-auth-flaws-01 also covers `/auth/reset` (predictable md5(username) token).
- php-business-logic-01 also covers `/orders/coupon` (unlimited coupon reuse).
- php-broken-access-control-01 also covers `DELETE /admin/users/{id}`.
