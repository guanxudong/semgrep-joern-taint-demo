# Ground Truth — perl-cgi

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

Route convention: there is no routing framework. Each action is a standalone
CGI script under `cgi-bin/`, and the HTTP route is the script path relative to
`cgi-bin/` — script `cgi-bin/users/search.pl` serves route `/users/search.pl`.
CGI scripts are procedural; every script defines a `sub run` as its main body
(called at the bottom of the file), which is the entrypoint function named
below. Neither Semgrep nor Joern supports Perl — this target exercises the
no-engine degraded mode, where only the LLM (and tree-sitter) reads the code.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| pl-sqli-01 | vuln | A | sqli | 89 | shallow | GET /users/search.pl | search.pl run | DB.pm query (`selectall_arrayref`) | search.pl → DB.pm |
| pl-sqli-02 | vuln | A | sqli | 89 | deep | GET /users/lookup.pl | lookup.pl run | DB.pm query (`selectall_arrayref`) | lookup.pl → UserService.pm (field `_pending_name`) → DB.pm |
| pl-xss-01 | vuln | A | xss | 79 | shallow | GET /render/hello.pl | hello.pl run | hello.pl run (HTML concat) | hello.pl |
| pl-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools/ping.pl | ping.pl run | ping.pl run (`system`) | ping.pl |
| pl-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools/diagnose.pl | diagnose.pl run | ToolService.pm run_staged_diag (`system`) | diagnose.pl → ToolService.pm (field `_target`) |
| pl-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /files/download.pl | download.pl run | FileService.pm read_user_file (2-arg `open`) | download.pl → FileService.pm |
| pl-rce-01 | vuln | A | rce | 94 | shallow | POST /tools/calc.pl | calc.pl run | calc.pl run (string `eval`) | calc.pl |
| pl-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml/parse.pl | parse.pl run | parse.pl run (`expand_entities => 1`) | parse.pl |
| pl-deserialization-01 | vuln | A | deserialization | 502 | shallow | POST /profile/import.pl | import.pl run | import.pl run (`thaw`) | import.pl |
| pl-ssti-01 | vuln | A | ssti | 1336 | shallow | GET /render/preview.pl | preview.pl run | preview.pl run (`$tt->process`) | preview.pl |
| pl-idor-01 | vuln | B | idor | 639 | medium | GET /users/view.pl | view.pl run | — | view.pl → UserService.pm |
| pl-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /orders/transfer.pl | transfer.pl run | — | transfer.pl → OrderService.pm |
| pl-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /orders/withdraw.pl | withdraw.pl run | — | withdraw.pl → OrderService.pm |
| pl-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile/update.pl | update.pl run | — | update.pl |
| pl-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile/update.pl | update.pl run | — | update.pl |
| pl-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin/users.pl | users.pl run | — | users.pl → DB.pm |
| pl-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth/login.pl | login.pl run | — | login.pl → Config.pm |
| pl-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /users/search2.pl | search2.pl run | DBI placeholders | search2.pl → DB.pm |
| pl-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /users/me.pl | me.pl run | ownership checked | me.pl → UserService.pm |
| pl-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml/parse2.pl | parse2.pl run | entities disabled | parse2.pl |
| pl-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /files/download2.pl | download2.pl run | allow-list check | download2.pl → FileService.pm |
| pl-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /orders/withdraw2.pl | withdraw2.pl run | flock lockfile | withdraw2.pl → OrderService.pm |

Notes:
- pl-priv-esc-01 and pl-mass-assignment-01 share the same script on purpose
  (one flawed handler exhibiting two B-class weaknesses).
- pl-auth-flaws-01 also covers `/auth/reset.pl` (predictable md5(username) token).
- pl-business-logic-01 also covers `/orders/coupon.pl` (unlimited coupon reuse).
- pl-broken-access-control-01 also covers `/admin/delete.pl` (no authorization).
