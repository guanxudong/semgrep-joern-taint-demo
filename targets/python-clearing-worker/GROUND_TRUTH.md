# Ground Truth — python-clearing-worker

Clearing/reconciliation worker: consumes execution reports and settlement
file drops over a message bus (subject subscription) and directory watcher,
then reconciles, books balances and notifies ops.
Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to the
trigger); **B** = non-sink (reason forward from the handler).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Trigger | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|---------|---------------|---------------|-------|
| pycl-sqli-01 | vuln | A | sqli | 89 | shallow | MSG reconcile.diff | reconciliation.on_diff_query | store.py query_unsafe (`cur.execute`) | reconciliation.py → recon_repo.py → store.py |
| pycl-sqli-02 | vuln | A | sqli | 89 | deep | MSG execution.report | executions.on_execution_report | store.py execute_unsafe (`cur.execute`) | executions.py → recon_service.py (fields `_pending_*`) → recon_repo.py → store.py |
| pycl-xss-01 | vuln | A | xss | 79 | shallow | MSG reconcile.done | reconciliation.on_reconcile_done | notify_service.py render_result_email (HTML concat) | reconciliation.py → notify_service.py |
| pycl-cmdi-01 | vuln | A | cmdi | 78 | shallow | MSG notify.send | notifications.on_notify | archive_service.py notify_ops (`os.system`) | notifications.py → archive_service.py |
| pycl-cmdi-02 | vuln | A | cmdi | 78 | deep | MSG notify.send | notifications.on_notify | archive_service.py ArchiveService send_staged_alert (`os.system`) | notifications.py → archive_service.py (field `_pending_label`) |
| pycl-path-traversal-01 | vuln | A | path-traversal | 22 | medium | FILE settlement | settlement.on_settlement_file | archive_service.py import_attachment (`open`) | settlement.py → archive_service.py |
| pycl-rce-01 | vuln | A | rce | 94 | shallow | MSG alert.rule | reconciliation.on_alert_rule | rule_engine.py evaluate (`eval`) | reconciliation.py → rule_engine.py |
| pycl-xxe-01 | vuln | A | xxe | 611 | shallow | FILE settlement | settlement.on_settlement_file | parsers.py parse_settlement_xml (`resolve_entities=True`) | settlement.py → parsers.py |
| pycl-deserialization-01 | vuln | A | deserialization | 502 | shallow | MSG snapshot.load | reconciliation.on_load_snapshot | recon_service.py load_snapshot (`pickle.loads`) | reconciliation.py → recon_service.py |
| pycl-ssti-01 | vuln | A | ssti | 1336 | shallow | MSG notify.send | notifications.on_notify | notify_service.py render_notice (`from_string`) | notifications.py → notify_service.py |
| pycl-idor-01 | vuln | B | idor | 639 | medium | MSG reconcile.request | reconciliation.on_request | — | reconciliation.py → recon_service.py |
| pycl-business-logic-01 | vuln | B | business-logic | 840 | medium | FILE settlement | settlement.on_settlement_file | — | settlement.py → recon_service.py |
| pycl-race-condition-01 | vuln | B | race-condition | 367 | medium | MSG execution.report | executions.on_execution_report | — | executions.py → money_service.py |
| pycl-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | FILE settlement | settlement.on_settlement_file | — | settlement.py → recon_service.py |
| pycl-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | MSG execution.report | executions.on_execution_report | — | executions.py |
| pycl-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | MSG ops.run_batch | reconciliation.on_run_batch | — | reconciliation.py → recon_service.py |
| pycl-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | MSG reconcile.request | reconciliation.on_request | — | reconciliation.py → config/settings.py |
| pycl-safe-01 | SAFE | A | sqli (mimic) | 89 | — | MSG reconcile.diff_safe | reconciliation.on_diff_query_safe | parameterized query | reconciliation.py → recon_repo.py |
| pycl-safe-02 | SAFE | B | idor (mimic) | 639 | — | MSG reconcile.request_safe | reconciliation.on_request_safe | requester checked | reconciliation.py → recon_service.py |
| pycl-safe-03 | SAFE | A | xxe (mimic) | 611 | — | FILE settlement_safe | settlement.on_settlement_file_safe | defusedxml | settlement.py → parsers.py |
| pycl-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | FILE settlement_safe | settlement.on_settlement_file_safe | allow-list regex | settlement.py → archive_service.py |
| pycl-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | MSG execution.report_safe | executions.on_execution_report_safe | threading.Lock | executions.py → money_service.py |

Notes:
- pycl-cmdi-02 and pycl-cmdi-01 share MSG notify.send; the `defer` payload
  flag selects the staged path.
- pycl-sqli-02, pycl-race-condition-01 and pycl-mass-assignment-01 share
  MSG execution.report (one handler exhibiting three weaknesses).
- pycl-path-traversal-01, pycl-xxe-01, pycl-business-logic-01 and
  pycl-priv-esc-01 share FILE settlement (one handler, four weaknesses).
- pycl-idor-01 and pycl-auth-flaws-01 share MSG reconcile.request; the
  token check exists but is forgeable (md5 without a secret), so the
  endpoint stays reachable for an attacker — both findings stand.
- Handler registration lives in ingest/runner.py (`bus.subscribe` /
  `watcher.watch`); the trigger strings above are the registered
  subjects / watched file kinds.
