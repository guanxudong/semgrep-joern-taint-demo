# Ground Truth — python-flask

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| py-sqli-01 | vuln | A | sqli | 89 | shallow | GET /users/search | users.search | data/db.py query_unsafe (`cur.execute`) | users.py → db.py |
| py-sqli-02 | vuln | A | sqli | 89 | deep | GET /users/lookup | users.lookup | data/db.py query_unsafe (`cur.execute`) | users.py → user_service.py (field `_pending_name`) → db.py |
| py-xss-01 | vuln | A | xss | 79 | shallow | GET /render/hello | render.hello | render.py hello (HTML concat) | render.py |
| py-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools/ping | tools.ping | tools.py ping (`os.system`) | tools.py |
| py-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools/diagnose | tools.diagnose | tool_service.py run_staged_diag (`os.system`) | tools.py → tool_service.py (field `_target`) |
| py-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /files/download | files.download | file_service.py read_user_file (`open`) | files.py → file_service.py |
| py-rce-01 | vuln | A | rce | 94 | shallow | POST /tools/calc | tools.calc | tools.py calc (`eval`) | tools.py |
| py-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml/parse | xml.parse_xml | xml.py parse_xml (`resolve_entities=True`) | xml.py |
| py-deserialization-01 | vuln | A | deserialization | 502 | shallow | POST /profile/import | profile.import_profile | profile.py import_profile (`pickle.loads`) | profile.py |
| py-ssti-01 | vuln | A | ssti | 1336 | shallow | GET /render/preview | render.preview | render.py preview (`render_template_string`) | render.py |
| py-idor-01 | vuln | B | idor | 639 | medium | GET /users/&lt;id&gt; | users.get_user | — | users.py → user_service.py |
| py-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /orders/transfer | orders.transfer | — | orders.py → order_service.py |
| py-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /orders/withdraw | orders.withdraw | — | orders.py → order_service.py |
| py-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile/update | profile.update_profile | — | profile.py |
| py-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile/update | profile.update_profile | — | profile.py |
| py-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin/users | admin.list_all_users | — | admin.py → db.py |
| py-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth/login | auth.login | — | auth.py → config.py |
| py-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /users/search_safe | users.search_safe | parameterized query | users.py → db.py |
| py-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /users/me/&lt;id&gt; | users.get_own_profile | ownership checked | users.py → user_service.py |
| py-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml/parse_safe | xml.parse_xml_safe | defusedxml | xml.py |
| py-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /files/download_safe | files.download_safe | allow-list check | files.py → file_service.py |
| py-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /orders/withdraw_safe | orders.withdraw_safe | threading.Lock | orders.py → order_service.py |

Notes:
- py-priv-esc-01 and py-mass-assignment-01 share the same endpoint on purpose
  (one flawed handler exhibiting two B-class weaknesses).
- py-auth-flaws-01 also covers `/auth/reset` (predictable md5(username) token).
- py-business-logic-01 also covers `/orders/coupon` (unlimited coupon reuse).
- py-broken-access-control-01 also covers `DELETE /admin/users/<id>`.
