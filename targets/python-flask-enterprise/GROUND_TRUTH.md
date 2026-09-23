# Ground Truth — python-flask-enterprise

Enterprise-style target ("OrderFlow", a B2B order/inventory API): layered
blueprints → services → repositories → db, auth decorators, middleware,
utilities. **No `VULN:`/`SAFE:` markers in the source** — this file and
`ground_truth.json` are the only record, so neither the agent nor the LLM
judges can anchor on comments.

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| pye-sqli-01 | vuln | A | sqli | 89 | deep | GET /api/v1/users/search | users.search | data/db.py query_raw (`execute(sql)`) | users.py → user_service.py (field `_pending_search`) → user_repo.py → base.py → db.py |
| pye-sqli-02 | vuln | A | sqli | 89 | deep | GET /api/v1/orders | orders.list_orders | data/db.py query (`execute`) | orders.py → order_service.py → order_repo.py → base.py (ORDER BY interp) → db.py |
| pye-xss-01 | vuln | A | xss | 79 | medium | GET /api/v1/reports/preview | reports.preview | report_service.py preview_html (HTML concat) | reports.py → report_service.py |
| pye-xss-02 | vuln | A | xss | 79 | medium | GET /api/v1/reports/directory | reports.directory | report_service.py directory_html (HTML concat) | reports.py → report_service.py |
| pye-cmdi-01 | vuln | A | cmdi | 78 | medium | GET /api/v1/diagnostics/ping | diagnostics.ping | utils/shell.py ping_host (`os.popen`) | diagnostics.py → diagnostics_service.py → shell.py |
| pye-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /api/v1/diagnostics/trace | diagnostics.trace | utils/shell.py trace_host (`shell=True`) | diagnostics.py → diagnostics_service.py (field `_target`) → shell.py |
| pye-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /api/v1/files/download | files.download | files.py download (`open`) | files.py → utils/files.py (normpath, no containment) |
| pye-rce-01 | vuln | A | rce | 94 | medium | POST /api/v1/reports/computed | reports.computed | report_service.py computed_column (`eval`) | reports.py → report_service.py |
| pye-xxe-01 | vuln | A | xxe | 611 | medium | POST /api/v1/invoices/import | invoices.import_invoice | invoices.py _parse_invoice_xml (`resolve_entities=True`) | invoices.py |
| pye-deserialization-01 | vuln | A | deserialization | 502 | medium | POST /api/v1/admin/cache/restore | admin.restore_cache | cache_service.py restore (`pickle.loads`) | admin.py → cache_service.py |
| pye-deserialization-02 | vuln | A | deserialization | 502 | shallow | POST /api/v1/webhooks/import | webhooks.import_webhook | webhooks.py import_webhook (`yaml.load`) | webhooks.py |
| pye-ssti-01 | vuln | A | ssti | 1336 | medium | POST /api/v1/notifications/preview | notifications.preview | notification_service.py render_preview (`render_template_string`) | notifications.py → notification_service.py |
| pye-idor-01 | vuln | B | idor | 639 | medium | GET /api/v1/orders/&lt;id&gt; | orders.get_order | — | orders.py → order_service.py → order_repo.py |
| pye-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /api/v1/orders | orders.create_order | — | orders.py → order_service.py → order_repo.py |
| pye-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /api/v1/inventory/&lt;id&gt;/adjust | inventory.adjust_stock | — | inventory.py → inventory_service.py → product_repo.py |
| pye-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /api/v1/admin/promote | admin.promote | — | admin.py → user_service.py |
| pye-mass-assignment-01 | vuln | B | mass-assignment | 915 | medium | PATCH /api/v1/users/me | users.update_me | — | users.py → user_service.py → user_repo.py → base.py |
| pye-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /api/v1/admin/audit-log | admin.audit_log | — | admin.py → db.py |
| pye-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /api/v1/auth/password-reset/request | auth.request_reset | — | auth.py → auth_service.py → crypto.py |
| pye-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /api/v1/users/&lt;id&gt; | users.get_user | parameterized | users.py → user_service.py → user_repo.py → base.py → db.py |
| pye-safe-02 | SAFE | A | sqli (mimic) | 89 | — | GET /api/v1/inventory/search | inventory.search_products | parameterized LIKE | inventory.py → product_repo.py → db.py |
| pye-safe-03 | SAFE | A | xss (mimic) | 79 | — | GET /api/v1/users/&lt;id&gt;/card | users.user_card | escape_html everywhere | users.py → user_service.py |
| pye-safe-04 | SAFE | A | cmdi (mimic) | 78 | — | GET /api/v1/diagnostics/dns | diagnostics.dns | argv list, shell=False | diagnostics.py → diagnostics_service.py → shell.py |
| pye-safe-05 | SAFE | A | path-traversal (mimic) | 22 | — | GET /api/v1/files/avatar/&lt;name&gt; | files.avatar | basename + containment | files.py → utils/files.py |
| pye-safe-06 | SAFE | A | xxe (mimic) | 611 | — | POST /api/v1/invoices/preview-xml | invoices.preview_invoice | resolve_entities=False | invoices.py |
| pye-safe-07 | SAFE | A | deserialization (mimic) | 502 | — | POST /api/v1/webhooks/import-json | webhooks.import_webhook_json | json.loads + validation | webhooks.py → validators.py |
| pye-safe-08 | SAFE | B | idor (mimic) | 639 | — | GET /api/v1/orders/&lt;id&gt;/receipt | orders.get_receipt | ownership check | orders.py → order_service.py → order_repo.py |
| pye-safe-09 | SAFE | B | race-condition (mimic) | 367 | — | POST /api/v1/inventory/&lt;id&gt;/reserve | inventory.reserve_stock | atomic conditional UPDATE | inventory.py → inventory_service.py → product_repo.py |
| pye-safe-10 | SAFE | B | mass-assignment (mimic) | 915 | — | PATCH /api/v1/users/me/profile | users.update_me_profile | PROFILE_EDITABLE allowlist | users.py → user_service.py → user_repo.py |
| pye-safe-11 | SAFE | A | ssti (mimic) | 1336 | — | POST /api/v1/notifications/send-welcome | notifications.send_welcome | fixed template + context | notifications.py → notification_service.py |

Notes:
- pye-auth-flaws-01 also covers `/api/v1/auth/password-reset/confirm`
  (unlimited attempts, no token expiry check).
- The mass-assignment root cause is shared between services/user_service.py
  (`update_profile` passes the payload through) and repositories/base.py
  (`update_fields` allowlists `role`/`is_active` as normal columns).
- pye-xss-02's taint source is the `display_name` column (stored XSS), so the
  chain starts at the route even though data comes via user_repo.
- Several vulnerabilities sit behind correct-looking role decorators
  (`@require_role("admin")` on diagnostics, `"manager"` on invoice import):
  the decorator gates *who* can reach the sink, not *whether* the sink is
  exploitable — category A entries are about the dataflow, not the role gate.
