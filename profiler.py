from __future__ import annotations

import cProfile
import datetime
import io
import json
import logging
import marshal
import os
import pstats
import re
import time
import traceback
from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from threading import Thread
from typing import Any, Callable, Counter, Literal, NamedTuple, cast

import django.db.backends.utils as bakutils
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, load_backend, login
from django.core.handlers.wsgi import WSGIRequest
from django.core.serializers.json import DjangoJSONEncoder
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.template import TemplateDoesNotExist
from django.template.loader import get_template
from django.utils.deprecation import MiddlewareMixin

django_logger = logging.getLogger("django.db.backends")
logger = logging.getLogger(__file__)

__all__ = ["patch_cursor_debug_wrapper", "ProfilerMiddleware", "ForceAuthMiddleware"]


class StackTrace(NamedTuple):
    path: str
    line: int
    func: str


class SQlCallTraceData(NamedTuple):
    sql: str
    duration: float
    params: tuple[Any, ...]
    trace: tuple[StackTrace, ...]


class ProfilerSettings(NamedTuple):
    WARN_COUNT_QUERIES: int
    """Count queries for warning"""
    ERROR_COUNT_QUERIES: int
    """Count queries for error"""
    REQUEST_EXCLUDE_LIST: set[str]
    """Exclude list for request"""
    SQL_LOG_PATH: str
    """Path for save sql log default: `os.path.join(os.path.dirname(settings.BASE_DIR), "profiler_logs")`"""
    SQL_PROFILER_ENABLED: bool
    """Enable write log for sql queries"""
    PROFILER_VIEW_FILE_PATH: str
    """
    Path for save profiler view file 
    default: `os.path.join(os.path.dirname(settings.BASE_DIR), "profiler_logs", "profiler_view_{request_name}.prof")`
    """


sql_stacktrace_ctx = ContextVar[list[SQlCallTraceData]]("sql_stacktrace_ctx", default=[])


@lru_cache
def get_settings():
    return ProfilerSettings(
        WARN_COUNT_QUERIES=getattr(settings, "PROFILER_WARN_COUNT_QUERIES", 50),
        ERROR_COUNT_QUERIES=getattr(settings, "PROFILER_WARN_COUNT_QUERIES", 100),
        REQUEST_EXCLUDE_LIST=set[str](
            ("/favicon.ico", "/jsi18n/", "/admin/jsi18n/", "/media/", "/static/")
            + tuple(getattr(settings, "PROFILER_REQUEST_EXCLUDE_LIST", ()))
        ),
        SQL_LOG_PATH=getattr(
            settings, "PROFILER_SQL_LOG_PATH", os.path.join(os.path.dirname(settings.BASE_DIR), "profiler_logs")
        ),
        SQL_PROFILER_ENABLED=getattr(settings, "SQL_PROFILER_ENABLED", False),
        PROFILER_VIEW_FILE_PATH=getattr(
            settings,
            "PROFILER_VIEW_FILE_PATH",
            os.path.join(os.path.dirname(settings.BASE_DIR), "profiler_logs", "profiler_view_{request_name}.prof"),
        ),
    )


def _get_sql_type(sql_query: str):
    pattern = r"^\s*(SELECT|UPDATE|INSERT|DELETE)\b"
    match = re.match(pattern, sql_query, re.IGNORECASE)
    if match:
        return cast(Literal["SELECT", "INSERT", "UPDATE", "DELETE"], match.group(1).upper())
    return "SELECT"


def patch_cursor_debug_wrapper():
    """Monkey patch for loud sql queries"""

    bakutils.CursorDebugWrapper_orig = bakutils.CursorDebugWrapper  # type: ignore

    class CursorDebugWrapperLoud(bakutils.CursorDebugWrapper_orig):  # type: ignore

        @contextmanager
        def debug_sql(self, sql=None, params=None, use_last_executed_query=False, many=False):
            start = time.monotonic()
            try:
                yield
            finally:
                sql = cast(str, sql)
                params = cast(tuple[Any, ...], params)
                stop = time.monotonic()
                duration = stop - start
                if get_settings().SQL_PROFILER_ENABLED:
                    stack: traceback.StackSummary = traceback.extract_stack()
                    trace_data = SQlCallTraceData(
                        sql=sql,
                        duration=duration,
                        params=params,
                        trace=tuple(
                            [
                                StackTrace(path, lineno, func)
                                for path, lineno, func, line in stack
                                if "lib/python" not in path
                            ]
                        ),
                    )
                    sql_stacktrace_ctx.get().append(trace_data)

                if use_last_executed_query:
                    sql = self.db.ops.last_executed_query(self.cursor, sql, params)
                try:
                    times = len(params) if many else ""
                except TypeError:
                    # params could be an iterator.
                    times = "?"
                self.db.queries_log.append(
                    {
                        "sql": "%s times: %s" % (times, sql) if many else sql,
                        "time": "%.3f" % duration,
                    }
                )
                django_logger.debug(
                    "(%.3f) %s; args=%s",
                    duration,
                    sql,
                    params,
                    extra={"duration": duration, "sql": sql, "params": params},
                )

    bakutils.CursorDebugWrapper = CursorDebugWrapperLoud


class SafeJSONEncoder(DjangoJSONEncoder):
    def default(self, o):
        try:
            return super().default(o)
        except Exception:
            return str(o)


def json_pretty_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=4, cls=SafeJSONEncoder).encode("raw_unicode_escape").decode("unicode_escape")


def save_file_log(
    *,
    request: HttpRequest,
    response: HttpResponse,
    template_path: str | None,
    file_log_path: str,
    sql_stacktrace: list[SQlCallTraceData],
    time_executed: float,
):
    i = 0

    queries: dict[str, list[SQlCallTraceData]] = defaultdict(list)

    counter = {
        "SELECT": 0,
        "INSERT": 0,
        "UPDATE": 0,
        "DELETE": 0,
        "TOTAL": 0,
        "DUPLICATES": 0,
    }

    for item in sql_stacktrace:
        queries[item.sql].append(item)
        if len(queries[item.sql]) > 1:
            counter["DUPLICATES"] += 2 if len(queries[item.sql]) == 2 else 1
        counter["TOTAL"] += 1
        counter[_get_sql_type(item.sql)] += 1

    with open(file_log_path, "w") as f:
        f.write("# Profiler Request\n\n")
        f.write(f"### Call datetime {datetime.datetime.now().strftime('%H:%M:%S %d.%m.%Y')}\n\n")
        f.write(f"### Method: `{request.method}`\n\n")
        f.write(f"### Path: `{request.path}`\n\n")
        f.write(f"### Time executed: `{time_executed:.3f}` sec.\n\n")
        if template_path:
            f.write(f"### Template path: `{template_path}`\n\n")
        f.write("### Request Headers: \n\n")
        f.write(f"```json\n{json_pretty_dumps(dict(request.headers))}\n```\n\n")
        f.write(f"### Response status: `{response.status_code}`\n\n")
        f.write("### Response headers: \n\n")
        f.write(f"```json\n{json_pretty_dumps(dict(response.items()))}\n```\n\n")
        f.write("### SQL queries execute stats:\n\n")
        f.write(f"| {' | '.join(counter.keys())} |\r")
        f.write(f"|-{'-|-'.join(['-' * len(name) for name in counter.keys()])}-|\r")
        f.write(f"| {' | '.join([str(count).ljust(len(name)) for name, count in counter.items()])} |\n\n")
        f.write("### SQL queries execute stacktrace:\n\n")
        for sql, items in queries.items():
            avg_duration = sum(item.duration for item in items) / len(items)
            traces_counter = Counter([item.trace for item in items])
            if len(items) > 1:
                query_count = f"{i + 1}-{i + 1 + len(items)}"
            else:
                query_count = str(i + 1)
            f.write(
                f"#### Query `{query_count}/{counter['TOTAL']}`"
                f"Count calls: `{len(items)}` Avg Duration: `{avg_duration:.3f}` sec.\n\n"
            )
            f.write(f"```sql\n{sql}\n```\n\n")
            f.write("### Params:\n\n")
            f.write("<details>\n\n")
            for item in items:
                f.write(f"```json\n{json_pretty_dumps(item.params)}\n```\n\n")
            f.write("</details>\n\n")
            f.write("### Stacktrace:\n\n")
            f.write("<details>\n\n")

            for traces, count in traces_counter.items():
                i += count
                f.write(f"### call count: `{count}`\n\n")
                f.write("<details>\n\n")
                f.write("```python\n")
                for trace in traces:
                    if __file__ == trace.path:
                        continue
                    f.write(f"{trace.path}:{trace.line} {trace.func}\n")
                f.write("```\n\n")
                f.write("</details>\n\n")
                print(
                    "\rProgress save file %s: %s%%" % (file_log_path, round(100 / (float(counter["TOTAL"]) / i), 2)),
                    end="\r",
                )
            f.write("</details>\n\n")
            f.write("---\n\n")


class ProfilerMiddleware(MiddlewareMixin):

    profiler: cProfile.Profile | None = None
    time_start_ctx = ContextVar[float]("time_start")

    def _request_is_ajax(self, request: WSGIRequest):
        return request.headers.get("x-requested-with") == "XMLHttpRequest"

    def _get_request_name(self, request: HttpRequest):
        return "__".join(filter(bool, request.path.split("/"))) or "index"

    def _get_template_path(self, response: HttpResponse):
        try:
            if not response["Content-Type"].startswith("text/html"):
                return
        except KeyError:
            return
        template_names: list[str] | str | None = getattr(response, "template_name", None)
        if template_names:
            if not isinstance(template_names, list):
                template_names = [template_names]
            template_path: str = template_names[0]
            if settings.TEMPLATE_DEBUG:
                for template_name in template_names:
                    try:
                        source = get_template(template_name)
                        template_path = source.origin.name  # type: ignore
                    except (TemplateDoesNotExist, IndexError, AttributeError) as e:
                        logger.debug(f"Error get template path: {e}")
            return template_path

    def _save_sql_stacktrace(
        self,
        request: WSGIRequest,
        response: HttpResponse,
        template_path: str | None,
        sql_stacktrace: list[SQlCallTraceData],
        time_executed: float,
    ):
        if not os.path.exists(get_settings().SQL_LOG_PATH):
            os.makedirs(get_settings().SQL_LOG_PATH)

        file_name = f"profiler_{(request.method or 'get').lower()}_" f"{self._get_request_name(request)}.md"
        file_log_path = os.path.join(get_settings().SQL_LOG_PATH, file_name)
        Thread(
            target=save_file_log,
            kwargs=dict(
                request=request,
                response=response,
                template_path=template_path,
                file_log_path=file_log_path,
                sql_stacktrace=sql_stacktrace,
                time_executed=time_executed,
            ),
        ).start()
        logger.debug(f"Save sql stacktrace to: {file_log_path}")

    def can(self, request: WSGIRequest):
        if settings.DEBUG:
            if next(filter(request.path.startswith, get_settings().REQUEST_EXCLUDE_LIST), None):
                return False
            return True

    def can_prof(self, request: WSGIRequest):
        return self.can(request) and "prof" in request.GET

    def process_view(
        self,
        request: WSGIRequest,
        callback: Callable[..., Any],
        callback_args: tuple[Any, ...],
        callback_kwargs: dict[str, Any],
    ):
        if self.can_prof(request):
            args = (request,) + callback_args
            try:
                return self.profiler.runcall(callback, *args, **callback_kwargs)
            except Exception as e:
                logger.exception(e)

    def process_request(self, request: WSGIRequest):
        sql_stacktrace_ctx.set([])

        if self.can_prof(request):
            self.profiler = cProfile.Profile()

        if self.can(request):
            self.time_start_ctx.set(time.monotonic())
            self.request_name = "request: %s %s (AJAX %s)" % (
                request.method,
                request.path,
                self._request_is_ajax(request),
            )

    def process_response(self, request: WSGIRequest, response: HttpResponse):

        if self.can_prof(request):
            self.profiler.create_stats()

        if self.can(request):
            passed = time.monotonic() - self.time_start_ctx.get()
            logger.debug(f"{self.request_name} passed: {passed:.3f}")
            template_path = self._get_template_path(response)
            if template_path:
                logger.debug(f"Template path: {template_path}")

            sql_stacktrace = sql_stacktrace_ctx.get()
            count_queries = len(sql_stacktrace)

            if count_queries > get_settings().ERROR_COUNT_QUERIES:
                logger.error(f"{self.request_name}: Count sql queries: {count_queries}")
            elif count_queries > get_settings().WARN_COUNT_QUERIES:
                logger.warning(f"{self.request_name}: Count sql queries: {count_queries}")
            else:
                logger.debug(f"{self.request_name}: Count sql queries: {count_queries}")

            for query_stack in sql_stacktrace:
                if query_stack.duration > 0.1:
                    sql = query_stack.sql
                    if len(sql) > 300:
                        sql = sql[:300] + "..."
                    logger.warning(f"Heavy SQL query: `{sql}` Duration: `{query_stack.duration:.3f}`")
            if get_settings().SQL_PROFILER_ENABLED:
                self._save_sql_stacktrace(request, response, template_path, sql_stacktrace, passed)

        if self.can_prof(request):
            if "read" in request.GET:
                buff = io.StringIO()
                stats = pstats.Stats(self.profiler, stream=buff)
                stats.strip_dirs().sort_stats(request.GET.get("sort", "time"))
                stats.print_stats(int(request.GET.get("count", 100)))
                response = HttpResponse(f"<pre>{buff.getvalue()}</pre>")
            else:
                output = marshal.dumps(self.profiler.stats)
                if not os.path.exists(os.path.dirname(get_settings().PROFILER_VIEW_FILE_PATH)):
                    os.makedirs(os.path.dirname(get_settings().PROFILER_VIEW_FILE_PATH))
                with open(
                    get_settings().PROFILER_VIEW_FILE_PATH.format(request_name=self._get_request_name(request)), "wb"
                ) as f:
                    f.write(output)
        return response


class ForceAuthMiddleware(MiddlewareMixin):
    """
    Middleware for force login in user by `fl` GET parameter
    example: `?fl=1` or `?fl=admin`
    include after `django.contrib.sessions.middleware.SessionMiddleware`
    """

    def process_request(self, request: HttpRequest):
        self.force_login(request)

    def force_login(self, request: HttpRequest):
        from django.contrib.auth.models import AbstractUser

        force_login: str | None = request.GET.get("fl", getattr(settings, "FORCE_AUTH_USER_PK", None))
        if force_login:
            pk: int | None = None
            need_admin: bool = False
            try:
                pk = int(force_login)
            except (ValueError, TypeError):
                need_admin = force_login == "admin"
            user = cast(AbstractUser | None, getattr(request, "user", None))
            if user is not None and user.is_authenticated:
                if need_admin and user.is_superuser:
                    return
                if pk == request.user.pk:
                    return
            user_model = cast(type[AbstractUser], get_user_model())
            if pk:
                user = user_model.objects.filter(pk=pk).first()
            elif need_admin:
                user = user_model.objects.filter(is_superuser=True).first()
            if user:
                backend = load_backend(settings.AUTHENTICATION_BACKENDS[0])
                user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)  # type: ignore
                login(request, user)
                messages.success(
                    request,
                    f"Force login in user: {user.pk} {user.username} {user.first_name} {user.last_name}",
                )
            else:
                logger.error(f"Not found User for `{force_login}`")
                messages.error(request, f"Not found User for `{force_login}`")
