# Ground Truth — perl-clearing-worker

Clearing/reconciliation worker (legacy Perl ops pipeline): consumes execution
reports and settlement file drops over a subject-based message bus and
directory watcher, then reconciles, books balances and notifies ops.
Mirror of python-clearing-worker in Perl idioms (plain-OO modules under
lib/MyApp, worker bootstrap in bin/).
Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to the
trigger); **B** = non-sink (reason forward from the handler).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Trigger | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|---------|---------------|---------------|-------|
| plcl-sqli-01 | vuln | A | sqli | 89 | shallow | MSG reconcile.diff | Reconciliation.on_diff_query | ReconRepo.pm find_unmatched (`select_rows`) | Reconciliation.pm → ReconRepo.pm |
| plcl-sqli-02 | vuln | A | sqli | 89 | deep | MSG execution.report | Executions.on_execution_report | ReconRepo.pm insert_record (`do_sql`) | Executions.pm → ReconService.pm (fields `_pending_*`) → ReconRepo.pm |
| plcl-xss-01 | vuln | A | xss | 79 | shallow | MSG reconcile.done | Reconciliation.on_reconcile_done | NotifyService.pm render_result_email (HTML concat) | Reconciliation.pm → NotifyService.pm |
| plcl-cmdi-01 | vuln | A | cmdi | 78 | shallow | MSG notify.send | Notifications.on_notify | ArchiveService.pm notify_ops (`system`) | Notifications.pm → ArchiveService.pm |
| plcl-cmdi-02 | vuln | A | cmdi | 78 | deep | MSG notify.send | Notifications.on_notify | ArchiveService.pm send_staged_alert (`system`) | Notifications.pm → ArchiveService.pm (field `_pending_label`) |
| plcl-path-traversal-01 | vuln | A | path-traversal | 22 | medium | FILE settlement | Settlement.on_settlement_file | ArchiveService.pm import_attachment (`open`) | Settlement.pm → ArchiveService.pm |
| plcl-rce-01 | vuln | A | rce | 94 | shallow | MSG alert.rule | Reconciliation.on_alert_rule | RuleEngine.pm evaluate (`eval $expr`) | Reconciliation.pm → RuleEngine.pm |
| plcl-xxe-01 | vuln | A | xxe | 611 | shallow | FILE settlement | Settlement.on_settlement_file | Parser.pm parse_settlement_xml (`expand_entities => 1`) | Settlement.pm → Parser.pm |
| plcl-deserialization-01 | vuln | A | deserialization | 502 | shallow | MSG snapshot.load | Reconciliation.on_load_snapshot | ReconService.pm load_snapshot (`thaw`) | Reconciliation.pm → ReconService.pm |
| plcl-ssti-01 | vuln | A | ssti | 1336 | shallow | MSG notify.send | Notifications.on_notify | NotifyService.pm render_notice (`[% `) | Notifications.pm → NotifyService.pm |
| plcl-idor-01 | vuln | B | idor | 639 | medium | MSG reconcile.request | Reconciliation.on_request | — | Reconciliation.pm → ReconService.pm |
| plcl-business-logic-01 | vuln | B | business-logic | 840 | medium | FILE settlement | Settlement.on_settlement_file | — | Settlement.pm → ReconService.pm |
| plcl-race-condition-01 | vuln | B | race-condition | 367 | medium | MSG execution.report | Executions.on_execution_report | — | Executions.pm → MoneyService.pm |
| plcl-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | FILE settlement | Settlement.on_settlement_file | — | Settlement.pm → ReconService.pm |
| plcl-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | MSG execution.report | Executions.on_execution_report | — | Executions.pm |
| plcl-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | MSG ops.run_batch | Reconciliation.on_run_batch | — | Reconciliation.pm → ReconService.pm |
| plcl-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | MSG reconcile.request | Reconciliation.on_request | — | Reconciliation.pm → Config.pm |
| plcl-safe-01 | SAFE | A | sqli (mimic) | 89 | — | MSG reconcile.diff_safe | Reconciliation.on_diff_query_safe | parameterized query | Reconciliation.pm → ReconRepo.pm |
| plcl-safe-02 | SAFE | B | idor (mimic) | 639 | — | MSG reconcile.request_safe | Reconciliation.on_request_safe | requester checked | Reconciliation.pm → ReconService.pm |
| plcl-safe-03 | SAFE | A | xxe (mimic) | 611 | — | FILE settlement_safe | Settlement.on_settlement_file_safe | entities disabled | Settlement.pm → Parser.pm |
| plcl-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | FILE settlement_safe | Settlement.on_settlement_file_safe | allow-list regex | Settlement.pm → ArchiveService.pm |
| plcl-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | MSG execution.report_safe | Executions.on_execution_report_safe | flock | Executions.pm → MoneyService.pm |

Notes:
- plcl-cmdi-02 and plcl-cmdi-01 share MSG notify.send; the `defer` payload
  flag selects the staged path.
- plcl-sqli-02, plcl-race-condition-01 and plcl-mass-assignment-01 share
  MSG execution.report (one handler exhibiting three weaknesses).
- plcl-path-traversal-01, plcl-xxe-01, plcl-business-logic-01 and
  plcl-priv-esc-01 share FILE settlement (one handler, four weaknesses).
- plcl-idor-01 and plcl-auth-flaws-01 share MSG reconcile.request; the
  token check exists but is forgeable (md5 without a secret), so the
  endpoint stays reachable for an attacker — both findings stand.
- Handler registration lives in bin/clearing_worker.pl
  (`MyApp::Bus::subscribe` / `MyApp::Watcher::watch`).
