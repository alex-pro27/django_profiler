# SQL profiler for django

__python version >= 3.8__

## Installation:
First you need to patch DjangoDebugWrapper
in the local settings file at the very top (before importing the basic settings):

local.py
```python
from .profiler import patch_cursor_debug_wrapper
patch_cursor_debug_wrapper()

```
Next, connect ProfilerMiddleware to the very top of the middleware list:
```python
...

MIDDLEWARE = list(MIDDLEWARE)
MIDDLEWARE.insert(0, "my_project.settings.profiler.ProfilerMiddleware")
SQL_PROFILER_ENABLED = True  # Enable logging

```


### specificity:
Saves log files in markdown format

Example:

# Profiler Request

### Call datetime 12:51:03 25.05.2024

### Method: `GET`

### Path: `/api/v1/config/`

### Time executed: `0.029` sec.

### Request Headers: 

```json
{
    "Content-Length": "",
    "Content-Type": "text/plain",
    "Host": "127.0.0.1:8000",
    "Connection": "keep-alive",\
    "Accept": "application/json, text/plain, */*",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",7
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "http://127.0.0.1:8000/",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US;q=0.9,en;q=0.8",
    "Cookie": "django_language=en; toggle_sidebar=True; csrftoken=dbBNOQJGAc0hqG3H3HJdrBLG4IKmX2qQSagD3P3DyO523t9pFYqB1njumgCWfDyh; sessionid=nskd7n8ni0rmtptp2ro1yj8mwn13m301"
}
```

### Response status: `200`

### Response headers: 

```json
{
    "Content-Type": "application/json",
    "Allow": "GET, HEAD, OPTIONS",
    "X-Frame-Options": "DENY",
    "Content-Length": "13337",
    "Vary": "Accept-Language, Cookie",
    "Content-Language": "ru"
}
```

### SQL queries execute stats:

| SELECT | INSERT | UPDATE | DELETE | TOTAL | DUPLICATES |
|--------|--------|--------|--------|-------|------------|
| 4      | 0      | 0      | 0      | 3     | 0          |

### SQL queries execute stacktrace:

#### Query `1/4`Count calls: `1` Avg Duration: `0.002` sec.

```sql
SELECT "django_session"."session_key", "django_session"."session_data", "django_session"."expire_date" FROM "django_session" WHERE ("django_session"."expire_date" > %s AND "django_session"."session_key" = %s) LIMIT 21
```

### Params:

<details>

```json
[
    "2024-05-25T12:51:03.433",
    "nskd7n8ni0rmtptp2ro1yj8mwn13m301"
]
```

</details>

### Stacktrace:

<details>

### call count: `1`

<details>

```python
/my_project/core/middleware.py:291 process_request
/my_project/core/middleware.py:284 can
```

</details>

</details>

---

#### Query `2/4`Count calls: `1` Avg Duration: `0.002` sec.

```sql
SELECT "core_user"."id", "core_user"."password", "core_user"."username", "core_user"."first_name", "core_user"."last_name", "core_user"."middle_name", "core_user"."email", "core_user"."email_confirmed", "core_user"."is_staff", "core_user"."is_active", "core_user"."date_joined", "core_user"."updated_at", "core_user"."verified", "core_user"."time_zone_id", "core_user"."blitz_id", "core_user"."lft", "core_user"."rght", "core_user"."tree_id", "core_user"."level", "core_timezone"."id", "core_timezone"."timezone_code", "core_timezone"."timezone_rule", "core_timezone"."timezone_summertime", "core_timezone"."timezone_shift" FROM "core_user" LEFT OUTER JOIN "core_timezone" ON ("core_user"."time_zone_id" = "core_timezone"."id") WHERE "core_user"."id" = %s LIMIT 21
```

### Params:

<details>

```json
[
    383
]
```

</details>

### Stacktrace:

<details>

### call count: `1`

<details>

```python
/my_project/core/middleware.py:291 process_request
/my_project/core/middleware.py:284 can
```

</details>

</details>

---

#### Query `3/4`Count calls: `1` Avg Duration: `0.001` sec.

```sql
SELECT ("roles_users"."user_id") AS "_prefetch_related_val_user_id", "roles"."id", "roles."name", "roles"."code", "roles"."all_groups", "roles"."all_companies", "roles"."parent_id", "roles"."managed_by_external" FROM "roles" INNER JOIN "roles_users" ON ("roles"."id" = "roles_users"."rolesrm_id") WHERE "roles_users"."user_id" IN (%s)
```

### Params:

<details>

```json
[
    383
]
```

</details>

### Stacktrace:

<details>

### call count: `1`

<details>

```python
/my_project/core/middleware.py:291 process_request
/my_project/core/middleware.py:284 can
```

</details>

</details>

---
