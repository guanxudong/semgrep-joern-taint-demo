# Ground Truth — java-spring

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| java-sqli-01 | vuln | A | sqli | 89 | shallow | GET /users/search | UserController.search | data/UserRepository.java queryUnsafe (`executeQuery`) | UserController → UserRepository |
| java-sqli-02 | vuln | A | sqli | 89 | deep | GET /users/lookup | UserController.lookup | data/UserRepository.java queryUnsafe (`executeQuery`) | UserController → UserService (field `pendingName`) → UserRepository |
| java-xss-01 | vuln | A | xss | 79 | shallow | GET /render/hello | RenderController.hello | RenderController.hello (HTML concat) | RenderController |
| java-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools/ping | ToolController.ping | ToolController.ping (`Runtime.exec`) | ToolController |
| java-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools/diagnose | ToolController.diagnose | utils/ExecUtil.java run (`Runtime.exec`) | ToolController → ToolService (field `target`) → ExecUtil |
| java-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /files/download | FileController.download | utils/FileUtil.java read (`Files.readAllBytes`) | FileController → FileService → FileUtil |
| java-rce-01 | vuln | A | rce | 94 | shallow | POST /tools/calc | ToolController.calc | ToolController.calc (`ScriptEngine.eval`) | ToolController |
| java-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml/parse | XmlController.parse | XmlController.parse (`DocumentBuilder.parse`) | XmlController |
| java-deserialization-01 | vuln | A | deserialization | 502 | medium | POST /profile/import | ProfileController.importProfile | ProfileController.importProfile (`readObject`) | ProfileController |
| java-ssti-01 | vuln | A | ssti | 1336 | medium | POST /render/preview | RenderController.preview | RenderController.preview (`new Template`) | RenderController |
| java-idor-01 | vuln | B | idor | 639 | medium | GET /users/{id} | UserController.getUser | — | UserController → UserService |
| java-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /orders/transfer | OrderController.transfer | — | OrderController → OrderService |
| java-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /orders/withdraw | OrderController.withdraw | — | OrderController → OrderService |
| java-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile/update | ProfileController.updateProfile | — | ProfileController |
| java-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile/update | ProfileController.updateProfile | — | ProfileController |
| java-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin/users | AdminController.listAllUsers | — | AdminController → UserRepository |
| java-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth/login | AuthController.login | — | AuthController → AppConfig |
| java-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /users/search_safe | UserController.searchSafe | parameterized PreparedStatement | UserController → UserRepository |
| java-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /users/me/{id} | UserController.getOwnProfile | ownership checked | UserController → UserService |
| java-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml/parse_safe | XmlController.parseSafe | DTD disabled | XmlController |
| java-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /files/download_safe | FileController.downloadSafe | allow-list check | FileController → FileService |
| java-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /orders/withdraw_safe | OrderController.withdrawSafe | synchronized block | OrderController → OrderService |

Notes:
- java-priv-esc-01 and java-mass-assignment-01 share the same endpoint on purpose
  (one flawed handler exhibiting two B-class weaknesses).
- java-auth-flaws-01 also covers `/auth/reset` (predictable md5(username) token).
- java-business-logic-01 also covers `/orders/coupon` (unlimited coupon reuse).
- java-broken-access-control-01 also covers `DELETE /admin/users/{id}`.
