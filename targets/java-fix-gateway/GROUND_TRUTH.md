# Ground Truth — java-fix-gateway

FIX-style order gateway: counterparties connect over TCP and send
newline-delimited `tag=value` messages; the MsgType (tag 35) is dispatched
through a registry (protocol/MessageRouter, wired in
protocol/GatewayServer) to handler methods in commands/.
Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to the
command); **B** = non-sink (reason forward from the handler).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Trigger | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|---------|---------------|---------------|-------|
| jtg-sqli-01 | vuln | A | sqli | 89 | shallow | CMD ORDER_STATUS | QueryCommands.onOrderQuery | OrderRepository.java findByClOrdId (`executeQuery`) | QueryCommands.java → OrderRepository.java |
| jtg-sqli-02 | vuln | A | sqli | 89 | deep | CMD NEWORDER | OrderCommands.onNewOrder | OrderRepository.java insertOrder (`executeUpdate`) | OrderCommands.java → OrderService.java (fields `pending*`) → OrderRepository.java |
| jtg-xss-01 | vuln | A | xss | 79 | shallow | CMD EXPORT_REPORT | AdminCommands.onExportReport | ReportService.java renderBlotter (HTML concat) | AdminCommands.java → ReportService.java |
| jtg-cmdi-01 | vuln | A | cmdi | 78 | shallow | CMD DIAG | AdminCommands.onDiag | OpsService.java notifyOps (`exec`) | AdminCommands.java → OpsService.java |
| jtg-cmdi-02 | vuln | A | cmdi | 78 | deep | CMD MD_ALERT | MarketDataCommands.onMdAlert | OpsService.java sendStagedAlert (`exec`) | MarketDataCommands.java → OpsService.java (field `pendingLabel`) |
| jtg-path-traversal-01 | vuln | A | path-traversal | 22 | medium | CMD EXPORT_REPORT | AdminCommands.onExportReport | ReportService.java exportReport (`new File`) | AdminCommands.java → ReportService.java |
| jtg-rce-01 | vuln | A | rce | 94 | shallow | CMD MD_RULE | MarketDataCommands.onMdRule | RuleEngine.java evaluate (`eval(`) | MarketDataCommands.java → RuleEngine.java |
| jtg-xxe-01 | vuln | A | xxe | 611 | shallow | CMD IMPORT_REFDATA | AdminCommands.onImportRefData | RefDataService.java loadRefData (`parse(`) | AdminCommands.java → RefDataService.java |
| jtg-deserialization-01 | vuln | A | deserialization | 502 | shallow | CMD RESTORE_SESSION | AdminCommands.onRestoreSession | SessionStore.java restore (`readObject`) | AdminCommands.java → SessionStore.java |
| jtg-ssti-01 | vuln | A | ssti | 1336 | shallow | CMD SEND_NOTICE | AdminCommands.onNotice | NotifyService.java renderNotice (`var t = `` `) | AdminCommands.java → NotifyService.java |
| jtg-idor-01 | vuln | B | idor | 639 | medium | CMD ORDER_STATUS | QueryCommands.onOrderQuery | — | QueryCommands.java → OrderRepository.java |
| jtg-business-logic-01 | vuln | B | business-logic | 840 | medium | CMD NEWORDER | OrderCommands.onNewOrder | — | OrderCommands.java → OrderService.java |
| jtg-race-condition-01 | vuln | B | race-condition | 367 | medium | CMD NEWORDER | OrderCommands.onNewOrder | — | OrderCommands.java → PositionService.java |
| jtg-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | CMD NEWORDER | OrderCommands.onNewOrder | — | OrderCommands.java |
| jtg-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | CMD NEWORDER | OrderCommands.onNewOrder | — | OrderCommands.java → OrderService.java |
| jtg-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | CMD ADMIN_OP | AdminCommands.onAdmin | — | AdminCommands.java |
| jtg-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | CMD LOGON | SessionCommands.onLogon | — | SessionCommands.java → LoginService.java → GatewayConfig.java |
| jtg-safe-01 | SAFE | A | sqli (mimic) | 89 | — | CMD ORDER_STATUS_SAFE | QueryCommands.onOrderQuerySafe | PreparedStatement | QueryCommands.java → OrderRepository.java |
| jtg-safe-02 | SAFE | B | idor (mimic) | 639 | — | CMD ORDER_STATUS_SAFE | QueryCommands.onOrderQuerySafe | scoped by compId | QueryCommands.java → OrderRepository.java |
| jtg-safe-03 | SAFE | A | xxe (mimic) | 611 | — | CMD IMPORT_REFDATA_SAFE | AdminCommands.onImportRefDataSafe | doctype/entities disabled | AdminCommands.java → RefDataService.java |
| jtg-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | CMD EXPORT_REPORT_SAFE | AdminCommands.onExportReportSafe | allow-list regex | AdminCommands.java → ReportService.java |
| jtg-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | CMD NEWORDER_SAFE | OrderCommands.onNewOrderSafe | synchronized method | OrderCommands.java → PositionService.java |

Notes:
- jtg-xss-01 and jtg-path-traversal-01 share CMD EXPORT_REPORT (render +
  write in one handler).
- jtg-sqli-02, jtg-business-logic-01, jtg-race-condition-01,
  jtg-priv-esc-01 and jtg-mass-assignment-01 share CMD NEWORDER (one
  handler exhibiting five weaknesses).
- jtg-cmdi-01 (CMD DIAG) and jtg-cmdi-02 (CMD MD_ALERT) take different
  paths through OpsService: direct notify vs the staged field path.
- Handler registration lives in protocol/GatewayServer.buildRouter()
  (`router.register(msgType, handler)`); the trigger strings above are the
  registry keys. Custom tags: 8001 = requested role, 10000 = continuity
  token, 10001 = rule expression, 10002 = ref-data XML, 10003 = session
  blob, 10004 = notice template.
