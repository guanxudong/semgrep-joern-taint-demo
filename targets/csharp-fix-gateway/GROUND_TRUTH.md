# Ground Truth — csharp-fix-gateway

FIX-style order gateway: counterparties connect over TCP and send
newline-delimited `tag=value` messages; the MsgType (tag 35) is dispatched
through a registry (Protocol/MessageRouter, wired in
Protocol/GatewayServer) to handler methods in Commands/.
C# mirror of java-fix-gateway (same domain model, .NET idioms).
Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to the
command); **B** = non-sink (reason forward from the handler).
Difficulty: shallow = sink in the handler itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Trigger | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|---------|---------------|---------------|-------|
| cstg-sqli-01 | vuln | A | sqli | 89 | shallow | CMD ORDER_STATUS | QueryCommands.OnOrderQuery | OrderRepository.cs FindByClOrdId (`SqlCommand(`) | QueryCommands.cs → OrderRepository.cs |
| cstg-sqli-02 | vuln | A | sqli | 89 | deep | CMD NEWORDER | OrderCommands.OnNewOrder | OrderRepository.cs InsertOrder (`SqlCommand(`) | OrderCommands.cs → OrderService.cs (fields `_pending*`) → OrderRepository.cs |
| cstg-xss-01 | vuln | A | xss | 79 | shallow | CMD EXPORT_REPORT | AdminCommands.OnExportReport | ReportService.cs RenderBlotter (HTML concat) | AdminCommands.cs → ReportService.cs |
| cstg-cmdi-01 | vuln | A | cmdi | 78 | shallow | CMD DIAG | AdminCommands.OnDiag | OpsService.cs NotifyOps (`Process.Start`) | AdminCommands.cs → OpsService.cs |
| cstg-cmdi-02 | vuln | A | cmdi | 78 | deep | CMD MD_ALERT | MarketDataCommands.OnMdAlert | OpsService.cs SendStagedAlert (`Process.Start`) | MarketDataCommands.cs → OpsService.cs (field `_pendingLabel`) |
| cstg-path-traversal-01 | vuln | A | path-traversal | 22 | medium | CMD EXPORT_REPORT | AdminCommands.OnExportReport | ReportService.cs ExportReport (`Path.Combine`) | AdminCommands.cs → ReportService.cs |
| cstg-rce-01 | vuln | A | rce | 94 | shallow | CMD MD_RULE | MarketDataCommands.OnMdRule | RuleEngine.cs Evaluate (`Compute(`) | MarketDataCommands.cs → RuleEngine.cs |
| cstg-xxe-01 | vuln | A | xxe | 611 | shallow | CMD IMPORT_REFDATA | AdminCommands.OnImportRefData | RefDataService.cs LoadRefData (`LoadXml(`) | AdminCommands.cs → RefDataService.cs |
| cstg-deserialization-01 | vuln | A | deserialization | 502 | shallow | CMD RESTORE_SESSION | AdminCommands.OnRestoreSession | SessionStore.cs Restore (`Deserialize(`) | AdminCommands.cs → SessionStore.cs |
| cstg-ssti-01 | vuln | A | ssti | 1336 | shallow | CMD SEND_NOTICE | AdminCommands.OnNotice | NotifyService.cs RenderNotice (`CompileAssemblyFromSource`) | AdminCommands.cs → NotifyService.cs |
| cstg-idor-01 | vuln | B | idor | 639 | medium | CMD ORDER_STATUS | QueryCommands.OnOrderQuery | — | QueryCommands.cs → OrderRepository.cs |
| cstg-business-logic-01 | vuln | B | business-logic | 840 | medium | CMD NEWORDER | OrderCommands.OnNewOrder | — | OrderCommands.cs → OrderService.cs |
| cstg-race-condition-01 | vuln | B | race-condition | 367 | medium | CMD NEWORDER | OrderCommands.OnNewOrder | — | OrderCommands.cs → PositionService.cs |
| cstg-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | CMD NEWORDER | OrderCommands.OnNewOrder | — | OrderCommands.cs |
| cstg-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | CMD NEWORDER | OrderCommands.OnNewOrder | — | OrderCommands.cs → OrderService.cs |
| cstg-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | CMD ADMIN_OP | AdminCommands.OnAdmin | — | AdminCommands.cs |
| cstg-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | CMD LOGON | SessionCommands.OnLogon | — | SessionCommands.cs → LoginService.cs → GatewayConfig.cs |
| cstg-safe-01 | SAFE | A | sqli (mimic) | 89 | — | CMD ORDER_STATUS_SAFE | QueryCommands.OnOrderQuerySafe | parameterized query | QueryCommands.cs → OrderRepository.cs |
| cstg-safe-02 | SAFE | B | idor (mimic) | 639 | — | CMD ORDER_STATUS_SAFE | QueryCommands.OnOrderQuerySafe | scoped by compId | QueryCommands.cs → OrderRepository.cs |
| cstg-safe-03 | SAFE | A | xxe (mimic) | 611 | — | CMD IMPORT_REFDATA_SAFE | AdminCommands.OnImportRefDataSafe | DTD prohibited, resolver null | AdminCommands.cs → RefDataService.cs |
| cstg-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | CMD EXPORT_REPORT_SAFE | AdminCommands.OnExportReportSafe | allow-list regex | AdminCommands.cs → ReportService.cs |
| cstg-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | CMD NEWORDER_SAFE | OrderCommands.OnNewOrderSafe | lock | OrderCommands.cs → PositionService.cs |

Notes:
- cstg-xss-01 and cstg-path-traversal-01 share CMD EXPORT_REPORT (render +
  write in one handler).
- cstg-sqli-02, cstg-business-logic-01, cstg-race-condition-01,
  cstg-priv-esc-01 and cstg-mass-assignment-01 share CMD NEWORDER (one
  handler exhibiting five weaknesses).
- cstg-cmdi-01 (CMD DIAG) and cstg-cmdi-02 (CMD MD_ALERT) take different
  paths through OpsService: direct notify vs the staged field path.
- Handler registration lives in Protocol/GatewayServer.BuildRouter()
  (`router.Register(msgType, handler)`); the trigger strings above are the
  registry keys. Custom tags: 8001 = requested role, 10000 = continuity
  token, 10001 = rule expression, 10002 = ref-data XML, 10003 = session
  blob, 10004 = notice template.
