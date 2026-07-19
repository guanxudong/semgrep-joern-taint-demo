# Ground Truth — csharp-aspnet

Legend: **A** = sink-based (Semgrep finds sink, Joern traces back to entrypoint);
**B** = non-sink (Joern starts at the entrypoint and reasons forward).
Difficulty: shallow = sink in the action itself; medium = 2-3 file chain;
deep = 4+ hops and/or taint passed through an instance field.
`SAFE` entries are near-miss counter-examples that a correct tool must NOT flag.

| ID | Exp. | Cat | Type | CWE | Difficulty | Route | Entrypoint fn | Sink (A only) | Chain |
|----|------|-----|------|-----|-----------|-------|---------------|---------------|-------|
| cs-sqli-01 | vuln | A | sqli | 89 | shallow | GET /users/search | UsersController.Search | Data/UserRepository.cs QueryUnsafe (`ExecuteReader`) | UsersController → UserRepository |
| cs-sqli-02 | vuln | A | sqli | 89 | deep | GET /users/lookup | UsersController.Lookup | Data/UserRepository.cs QueryUnsafe (`ExecuteReader`) | UsersController → UserService (field `_pendingName`) → UserRepository |
| cs-xss-01 | vuln | A | xss | 79 | shallow | GET /render/hello | RenderController.Hello | RenderController.Hello (HTML concat) | RenderController |
| cs-cmdi-01 | vuln | A | cmdi | 78 | shallow | GET /tools/ping | ToolsController.Ping | ToolsController.Ping (`Process.Start`) | ToolsController |
| cs-cmdi-02 | vuln | A | cmdi | 78 | deep | GET /tools/diagnose | ToolsController.Diagnose | ToolService.cs RunStagedDiag (`Process.Start`) | ToolsController → ToolService (field `_target`) |
| cs-path-traversal-01 | vuln | A | path-traversal | 22 | medium | GET /files/download | FilesController.Download | FileService.cs ReadUserFile (`File.ReadAllText`) | FilesController → FileService |
| cs-rce-01 | vuln | A | rce | 94 | shallow | POST /tools/calc | ToolsController.Calc | ToolsController.Calc (`CompileAssemblyFromSource`) | ToolsController |
| cs-xxe-01 | vuln | A | xxe | 611 | shallow | POST /xml/parse | XmlController.Parse | XmlController.Parse (`DtdProcessing.Parse`) | XmlController |
| cs-deserialization-01 | vuln | A | deserialization | 502 | medium | POST /profile/import | ProfileController.ImportProfile | ProfileController.ImportProfile (`BinaryFormatter.Deserialize`) | ProfileController |
| cs-ssti-01 | vuln | A | ssti | 1336 | medium | POST /render/preview | RenderController.Preview | RenderController.Preview (`RunCompile`) | RenderController |
| cs-idor-01 | vuln | B | idor | 639 | medium | GET /users/{id} | UsersController.GetUser | — | UsersController → UserService |
| cs-business-logic-01 | vuln | B | business-logic | 840 | medium | POST /orders/transfer | OrdersController.Transfer | — | OrdersController → OrderService |
| cs-race-condition-01 | vuln | B | race-condition | 367 | medium | POST /orders/withdraw | OrdersController.Withdraw | — | OrdersController → OrderService |
| cs-priv-esc-01 | vuln | B | priv-esc | 269 | shallow | POST /profile/update | ProfileController.UpdateProfile | — | ProfileController |
| cs-mass-assignment-01 | vuln | B | mass-assignment | 915 | shallow | POST /profile/update | ProfileController.UpdateProfile | — | ProfileController |
| cs-broken-access-control-01 | vuln | B | broken-access-control | 862 | shallow | GET /admin/users | AdminController.ListAllUsers | — | AdminController → UserRepository |
| cs-auth-flaws-01 | vuln | B | auth-flaws | 287 | medium | POST /auth/login | AuthController.Login | — | AuthController → AppConfig |
| cs-safe-01 | SAFE | A | sqli (mimic) | 89 | — | GET /users/search_safe | UsersController.SearchSafe | parameterized SqlCommand | UsersController → UserRepository |
| cs-safe-02 | SAFE | B | idor (mimic) | 639 | — | GET /users/me/{id} | UsersController.GetOwnProfile | ownership checked | UsersController → UserService |
| cs-safe-03 | SAFE | A | xxe (mimic) | 611 | — | POST /xml/parse_safe | XmlController.ParseSafe | DtdProcessing.Prohibit | XmlController |
| cs-safe-04 | SAFE | A | path-traversal (mimic) | 22 | — | GET /files/download_safe | FilesController.DownloadSafe | allow-list check | FilesController → FileService |
| cs-safe-05 | SAFE | B | race-condition (mimic) | 367 | — | POST /orders/withdraw_safe | OrdersController.WithdrawSafe | lock (SyncRoot) | OrdersController → OrderService |

Notes:
- cs-priv-esc-01 and cs-mass-assignment-01 share the same endpoint on purpose
  (one flawed action exhibiting two B-class weaknesses).
- cs-auth-flaws-01 also covers `/auth/reset` (predictable Random() token).
- cs-business-logic-01 also covers `/orders/coupon` (unlimited coupon reuse).
- cs-broken-access-control-01 also covers `DELETE /admin/users/{id}`.
- Joern's C# frontend is less mature than the JVM/Python/JS ones; expect
  coarser CPGs here (attribute-based routing and model binding are only
  partially modeled).
