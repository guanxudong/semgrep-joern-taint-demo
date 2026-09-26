# Ground Truth — perl-mojo

Legend: **A** = sink-based (in the full pipeline Semgrep finds sink, Joern traces
back to entrypoint; Perl is supported by neither, so this target is read by
LLM agents and tree-sitter only — degraded mode); **B** = non-sink (reasoning
forward from the entrypoint).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.
This target intentionally carries NO in-source `VULN:`/`SAFE:` markers —
this file and `ground_truth.json` are the only record.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| pl-sqli-01 | vuln | A | sqli | 89 | shallow | GET /users/search | Users.search | DB.pm query (`selectall_arrayref($sql`) | Users.pm → DB.pm |
| pl-sqli-02 | vuln | A | sqli | 89 | deep | GET /users/lookup | Users.lookup | DB.pm query (`selectall_arrayref($sql`) | Users.pm → UserService.pm (field `_pending_name`) → DB.pm |
| pl-xss-01 | vuln | A | xss | 79 | shallow | GET /render/hello | Render.hello | Render.pm hello (HTML concat) | Render.pm |
| pl-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools/ping | Tools.ping | Tools.pm ping (`system`) | Tools.pm |
| pl-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools/diagnose | Tools.diagnose | ToolService.pm run_staged_diag (`qx($cmd)`) | Tools.pm → ToolService.pm (field `_target`) |
| pl-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /files/download | Files.download | FileService.pm read_file (2-arg `open`) | Files.pm → FileService.pm |
| pl-rce-01 | vuln | A | rce | 94 | shallow | POST /tools/calc | Tools.calc | Tools.pm calc (string `eval`) | Tools.pm |
| pl-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml/parse | Xml.parse | Xml.pm parse (`expand_entities(1)`) | Xml.pm |
| pl-deserialization-01 | vuln | A | deserialization | 502 | shallow | POST /profile/import | Profile.import_profile | Profile.pm import_profile (`Storable::thaw`) | Profile.pm |
| pl-ssti-01 | vuln | A | ssti | 1336 | shallow | GET /render/preview | Render.preview | Render.pm preview (`$tt->process(\$tpl`) | Render.pm |
| pl-idor-01 | vuln | B | idor | 639 | medium | GET /users/&lt;id&gt; | Users.get_user | — | Users.pm → UserService.pm |
| pl-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /orders/transfer | Orders.transfer | — | Orders.pm → OrderService.pm |
| pl-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /orders/withdraw | Orders.withdraw | — | Orders.pm → OrderService.pm |
| pl-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile/update | Profile.update_profile | — | Profile.pm |
| pl-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile/update | Profile.update_profile | — | Profile.pm |
| pl-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin/users | Admin.list_all_users | — | Admin.pm → DB.pm |
| pl-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth/login | Auth.login | — | Auth.pm → Config.pm |
| pl-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /users/search_prepared | Users.search_prepared | parameterized query | Users.pm → DB.pm |
| pl-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /users/me/&lt;id&gt; | Users.get_own_profile | ownership checked | Users.pm → UserService.pm |
| pl-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml/parse_basic | Xml.parse_basic | entity expansion off | Xml.pm |
| pl-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /files/download_listed | Files.download_listed | allow-list + 3-arg open | Files.pm → FileService.pm |
| pl-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /orders/withdraw_locked | Orders.withdraw_locked | flock(LOCK_EX) | Orders.pm → OrderService.pm |

Notes:
- pl-priv-esc-01 and pl-mass-assignment-01 share the same endpoint on purpose
  (one flawed handler exhibiting two B-class weaknesses).
- pl-auth-flaws-01 also covers `/auth/reset` (predictable md5(username) token).
- pl-business-logic-01 also covers `/orders/coupon` (unlimited coupon reuse).
- pl-broken-access-control-01 also covers `DELETE /admin/users/<id>`.
- Mirrors `targets/python-flask/` one-to-one (22 entries). Deliberate naming
  deviation: since this target has no in-source markers, safe-variant routes
  and functions use mechanism-describing names instead of the flask `_safe`
  suffix (`search_prepared`, `parse_basic`, `download_listed`,
  `withdraw_locked`); DB helpers are `query()`/`query_prepared()` rather than
  `query_unsafe()`/`query_safe()`.
- Deep-taint services (UserService, ToolService) are singletons holding taint
  in instance fields between method calls, mirroring the flask module-level
  service objects.
