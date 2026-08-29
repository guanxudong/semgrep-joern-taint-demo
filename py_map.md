# Repo Map: python-flask

Root: `/Users/xdguan/Code/semgrep-joern-taint-demo/targets/python-flask`  
Tool: tree-sitter  
Files indexed: 16

## Directory Tree

```
├── app.py  [other]
├── config.py  [config]
├── data/
│   └── db.py  [data]
├── routes/
│   ├── admin.py  [route]
│   ├── auth.py  [route]
│   ├── files.py  [route]
│   ├── orders.py  [route]
│   ├── profile.py  [route]
│   ├── render.py  [route]
│   ├── tools.py  [route]
│   ├── users.py  [route]
│   └── xml.py  [route]
└── services/
    ├── file_service.py  [service]
    ├── order_service.py  [service]
    ├── tool_service.py  [service]
    └── user_service.py  [service]
```

## HTTP Routes

| Method | Path | File | Function | Line |
|---|---|---|---|---|
| GET | `/admin/users` | routes/admin.py | `list_all_users` | 10 |
| DELETE | `/admin/users/<int:user_id>` | routes/admin.py | `delete_user` | 17 |
| POST | `/auth/login` | routes/auth.py | `login` | 13 |
| POST | `/auth/reset` | routes/auth.py | `request_reset` | 23 |
| GET | `/files/download` | routes/files.py | `download` | 10 |
| GET | `/files/download_safe` | routes/files.py | `download_safe` | 18 |
| POST | `/orders/transfer` | routes/orders.py | `transfer` | 10 |
| POST | `/orders/coupon` | routes/orders.py | `coupon` | 18 |
| POST | `/orders/withdraw` | routes/orders.py | `withdraw` | 26 |
| POST | `/orders/withdraw_safe` | routes/orders.py | `withdraw_safe` | 34 |
| POST | `/profile/update` | routes/profile.py | `update_profile` | 21 |
| POST | `/profile/import` | routes/profile.py | `import_profile` | 31 |
| GET | `/render/preview` | routes/render.py | `preview` | 8 |
| GET | `/render/hello` | routes/render.py | `hello` | 15 |
| GET | `/tools/ping` | routes/tools.py | `ping` | 12 |
| GET | `/tools/diagnose` | routes/tools.py | `diagnose` | 20 |
| POST | `/tools/calc` | routes/tools.py | `calc` | 29 |
| GET | `/users/search` | routes/users.py | `search` | 11 |
| GET | `/users/lookup` | routes/users.py | `lookup` | 19 |
| GET | `/users/<int:user_id>` | routes/users.py | `get_user` | 28 |
| GET | `/users/search_safe` | routes/users.py | `search_safe` | 35 |
| GET | `/users/me/<int:user_id>` | routes/users.py | `get_own_profile` | 43 |
| POST | `/xml/parse` | routes/xml.py | `parse_xml` | 11 |
| POST | `/xml/parse_safe` | routes/xml.py | `parse_xml_safe` | 20 |

### app.py  (other, python)
- imports: `flask`, `routes.users`, `routes.admin`, `routes.files`, `routes.tools`, `routes.xml`, `routes.render`, `routes.auth`, `routes.orders`, `routes.profile`
- L15 `function` **create_app**: `def create_app():`

### config.py  (config, python)
- (no top-level symbols)

### data/db.py  (data, python)
- imports: `sqlite3`, `config`
- L7 `function` **get_conn**: `def get_conn():`
- L11 `function` **query_unsafe**: `def query_unsafe(sql):`
- L22 `function` **query_safe**: `def query_safe(sql, params):`
- L33 `function` **execute_unsafe**: `def execute_unsafe(sql):`

### routes/admin.py  (route, python)
- imports: `flask`, `data`
- L11 `function` **list_all_users**: `def list_all_users():`
- L18 `function` **delete_user**: `def delete_user(user_id):`

### routes/auth.py  (route, python)
- imports: `hashlib`, `jwt`, `flask`, `config`
- L14 `function` **login**: `def login():`
- L24 `function` **request_reset**: `def request_reset():`

### routes/files.py  (route, python)
- imports: `flask`, `services`
- L11 `function` **download**: `def download():`
- L19 `function` **download_safe**: `def download_safe():`

### routes/orders.py  (route, python)
- imports: `flask`, `services`
- L11 `function` **transfer**: `def transfer():`
- L19 `function` **coupon**: `def coupon():`
- L27 `function` **withdraw**: `def withdraw():`
- L35 `function` **withdraw_safe**: `def withdraw_safe():`

### routes/profile.py  (route, python)
- imports: `pickle`, `flask`
- L7 `class` **User**: `class User:`
- L8 `method` **__init__** (in User): `def __init__(self):`
- L22 `function` **update_profile**: `def update_profile():`
- L32 `function` **import_profile**: `def import_profile():`

### routes/render.py  (route, python)
- imports: `flask`
- L9 `function` **preview**: `def preview():`
- L16 `function` **hello**: `def hello():`

### routes/tools.py  (route, python)
- imports: `os`, `flask`, `services.tool_service`
- L13 `function` **ping**: `def ping():`
- L21 `function` **diagnose**: `def diagnose():`
- L30 `function` **calc**: `def calc():`

### routes/users.py  (route, python)
- imports: `flask`, `data`, `services.user_service`
- L12 `function` **search**: `def search():`
- L20 `function` **lookup**: `def lookup():`
- L29 `function` **get_user**: `def get_user(user_id):`
- L36 `function` **search_safe**: `def search_safe():`
- L44 `function` **get_own_profile**: `def get_own_profile(user_id):`

### routes/xml.py  (route, python)
- imports: `flask`, `lxml`, `defusedxml`
- L12 `function` **parse_xml**: `def parse_xml():`
- L21 `function` **parse_xml_safe**: `def parse_xml_safe():`

### services/file_service.py  (service, python)
- imports: `os`, `config`
- L9 `function` **read_user_file**: `def read_user_file(name):`
- L16 `function` **read_whitelisted**: `def read_whitelisted(name):`

### services/order_service.py  (service, python)
- imports: `data`, `threading`
- L8 `function` **transfer**: `def transfer(src, dst, amount):`
- L16 `function` **apply_coupon**: `def apply_coupon(user, coupon):`
- L24 `function` **withdraw**: `def withdraw(user, amount):`
- L41 `function` **withdraw_safe**: `def withdraw_safe(user, amount):`

### services/tool_service.py  (service, python)
- imports: `os`
- L5 `class` **ToolService**: `class ToolService:`
- L6 `method` **__init__** (in ToolService): `def __init__(self):`
- L9 `method` **stage_target** (in ToolService): `def stage_target(self, host):`
- L12 `method` **run_staged_diag** (in ToolService): `def run_staged_diag(self):`

### services/user_service.py  (service, python)
- imports: `data`
- L5 `class` **UserService**: `class UserService:`
- L6 `method` **__init__** (in UserService): `def __init__(self):`
- L9 `method` **stage_name** (in UserService): `def stage_name(self, name):`
- L13 `method` **find_staged** (in UserService): `def find_staged(self):`
- L18 `method` **find_by_name** (in UserService): `def find_by_name(self, name):`
- L22 `method` **find_by_id** (in UserService): `def find_by_id(self, user_id):`
- L26 `method` **find_by_id_safe** (in UserService): `def find_by_id_safe(self, user_id):`

## Reference Graph

- app.py → routes/admin.py
- app.py → routes/auth.py
- app.py → routes/files.py
- app.py → routes/orders.py
- app.py → routes/profile.py
- app.py → routes/render.py
- app.py → routes/tools.py
- app.py → routes/users.py
- app.py → routes/xml.py
- data/db.py → config.py
- routes/admin.py → data/db.py
- routes/auth.py → config.py
- routes/files.py → services/file_service.py
- routes/orders.py → services/order_service.py
- routes/tools.py → services/tool_service.py
- routes/users.py → data/db.py
- routes/users.py → services/user_service.py
- services/file_service.py → config.py
- services/order_service.py → data/db.py
- services/user_service.py → data/db.py

Most referenced: `data/db.py` (4), `config.py` (3), `routes/admin.py` (1), `routes/auth.py` (1), `routes/files.py` (1), `routes/orders.py` (1), `routes/profile.py` (1), `routes/render.py` (1), `routes/tools.py` (1), `routes/users.py` (1)

