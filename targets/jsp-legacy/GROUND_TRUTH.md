# Ground Truth — jsp-legacy

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the page itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

> **Analysis note:** neither Semgrep nor Joern parses JSP. Pages are analyzed
> by transpiling them to plain Java with `scripts/jsp_to_java.py`
> (`pages/*.jsp` → `workspace/jsp-java/pages/<base>_jsp.java`, class
> `<base>_jsp`, entrypoint function `_jspService`) and running the whole
> java pipeline (`analysis/rules/sinks-java.yml`, javasrc2cpg, joern scripts)
> on the generated tree. Generated line N of a page maps back to JSP line
> `N - offset` via `workspace/jsp-java/manifest.json`.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| jsp-sqli-01 | vuln | A | sqli | 89 | shallow | GET /user_search.jsp | user_search_jsp._jspService | src/legacy/data/UserRepository.java queryUnsafe (`executeQuery`) | user_search.jsp → UserRepository |
| jsp-sqli-02 | vuln | A | sqli | 89 | deep | GET /user_lookup.jsp | user_lookup_jsp._jspService | src/legacy/data/UserRepository.java queryUnsafe (`executeQuery`) | user_lookup.jsp → UserService (field `pendingName`) → UserRepository |
| jsp-xss-01 | vuln | A | xss | 79 | shallow | GET /render_hello.jsp | render_hello_jsp._jspService | render_hello.jsp (`out.print` HTML concat; not matched by the return-based java xss rule) | render_hello.jsp |
| jsp-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools_ping.jsp | tools_ping_jsp._jspService | tools_ping.jsp (`Runtime.exec`) | tools_ping.jsp |
| jsp-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools_diagnose.jsp | tools_diagnose_jsp._jspService | src/legacy/util/ExecUtil.java run (`Runtime.exec`) | tools_diagnose.jsp → ToolService (field `target`) → ExecUtil |
| jsp-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /file_download.jsp | file_download_jsp._jspService | src/legacy/util/FileUtil.java read (`Files.readAllBytes`) | file_download.jsp → FileService → FileUtil |
| jsp-rce-01 | vuln | A | rce | 94 | shallow | POST /tools_calc.jsp | tools_calc_jsp._jspService | tools_calc.jsp (`ScriptEngine.eval`) | tools_calc.jsp |
| jsp-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml_parse.jsp | xml_parse_jsp._jspService | xml_parse.jsp (`DocumentBuilder.parse`) | xml_parse.jsp |
| jsp-deserialization-01 | vuln | A | deserialization | 502 | medium | POST /profile_import.jsp | profile_import_jsp._jspService | profile_import.jsp (`readObject`) | profile_import.jsp |
| jsp-ssti-01 | vuln | A | ssti | 1336 | medium | POST /render_preview.jsp | render_preview_jsp._jspService | render_preview.jsp (`new Template`) | render_preview.jsp |
| jsp-idor-01 | vuln | B | idor | 639 | medium | GET /user_view.jsp | user_view_jsp._jspService | — | user_view.jsp → UserService |
| jsp-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /order_transfer.jsp | order_transfer_jsp._jspService | — | order_transfer.jsp → OrderService |
| jsp-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /order_withdraw.jsp | order_withdraw_jsp._jspService | — | order_withdraw.jsp → OrderService |
| jsp-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile_update.jsp | profile_update_jsp._jspService | — | profile_update.jsp |
| jsp-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile_update.jsp | profile_update_jsp._jspService | — | profile_update.jsp |
| jsp-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin_users.jsp | admin_users_jsp._jspService | — | admin_users.jsp → UserRepository |
| jsp-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth_login.jsp | auth_login_jsp._jspService | — | auth_login.jsp → AppConfig |
| jsp-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /user_search_safe.jsp | user_search_safe_jsp._jspService | parameterized PreparedStatement | user_search_safe.jsp → UserRepository |
| jsp-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /user_view_safe.jsp | user_view_safe_jsp._jspService | ownership checked vs session uid | user_view_safe.jsp → UserService |
| jsp-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml_parse_safe.jsp | xml_parse_safe_jsp._jspService | DTD disabled | xml_parse_safe.jsp |
| jsp-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /file_download_safe.jsp | file_download_safe_jsp._jspService | allow-list check | file_download_safe.jsp → FileService |
| jsp-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /order_withdraw_safe.jsp | order_withdraw_safe_jsp._jspService | synchronized block | order_withdraw_safe.jsp → OrderService |

Notes:
- jsp-priv-esc-01 and jsp-mass-assignment-01 share the same page on purpose
  (one flawed scriptlet exhibiting two B-class weaknesses).
- jsp-auth-flaws-01 also covers `/auth_reset.jsp` (predictable md5(username) token).
- jsp-business-logic-01 also covers `/order_coupon.jsp` (unlimited coupon reuse).
- jsp-broken-access-control-01 also covers `POST /admin_delete.jsp`.
- jsp-xss-01 has no Semgrep hit: `analysis/rules/sinks-java.yml`'s xss rule
  only matches `return "<html>" + x`, while JSP writes via `out.print(...)`.
  The entry stays category A; its detection rests on the Joern + LLM layers.
