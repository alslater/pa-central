"""Request-body validation that must run before any route or schema sees it."""
import email.message
import json

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


def _is_json_content_type(content_type: str) -> bool:
    """Mirrors FastAPI's own JSON-detection exactly (routing.py's
    `get_request_handler`, `strict_content_type=True` — the default, and
    unoverridden by any route in this app): `application/json` OR any
    `application/*+json` subtype (`application/problem+json`,
    `application/vnd.api+json`, `application/ld+json`, ...). Matching a
    literal `"application/json"` alone left every `+json` media type
    completely unchecked — FastAPI still parses and dispatches them as
    JSON, so a lone surrogate arriving under one of those content types
    reached the exact UnicodeEncodeError crash this middleware exists to
    prevent, reproduced directly. Uses the same `email.message.Message`
    parser FastAPI itself uses (rather than a hand-rolled split), so this
    stays correct if FastAPI's own matching ever changes shape (e.g.
    parameter handling) without needing to track that separately.
    """
    message = email.message.Message()
    message["content-type"] = content_type
    if message.get_content_maintype() != "application":
        return False
    subtype = message.get_content_subtype()
    return subtype == "json" or subtype.endswith("+json")

# Every user-/admin-facing endpoint in this app is small JSON — the
# largest single field constraint anywhere in schemas/__init__.py is 4096
# bytes (scan_flags) and there is no file-upload/multipart path at all
# (see this module's own docstring). 1 MiB is generous headroom over any
# of those while still firmly bounding the unauthenticated buffering below.
MAX_INSPECTED_BODY_BYTES = 1024 * 1024

# Scan-ingest routes are the one legitimate exception: RepoScanResultIngest
# and ScanPayload (schemas/__init__.py) carry unbounded `findings`/`risks`
# lists (plus ScanPayload's raw scan output) with no per-item or list-length
# cap, and a genuinely large or long-neglected project can produce
# thousands of package-alert findings — plausibly several MB of JSON. These
# routes sit behind their own API-key auth (require_system_key /
# ApiKeyDep), checked downstream of this middleware, but the size cap here
# still applies before that runs (this middleware's whole reason for
# existing is to run before ANY downstream code) — so they need their own,
# much larger ceiling rather than either being crushed by the tight default
# or having no cap at all. 25 MiB is generous headroom over the rough
# worst-case estimate above while still bounding an unauthenticated sender
# who has learned the path (the API key check, downstream, is what
# actually gates a real attacker — this is a backstop against buffering an
# unbounded body before that check even runs).
MAX_INGEST_BODY_BYTES = 25 * 1024 * 1024
_LARGE_PAYLOAD_PATHS = frozenset({
    "/api/ingest/scans",
    "/api/ingest/repo-scan-result",
})


# The deepest nesting any real request body in this app needs: every
# dict/list-typed schema field (schemas/__init__.py) is a flat or
# near-flat container — `findings`/`risks`/`signals`: list[dict] of a
# handful of scalar keys each, `exclusions`: list[list[str]] — real
# examples in tests/*.py never exceed 2-3 levels total. 20 is generous
# headroom over any of those (5-10x) while remaining nowhere near where a
# component further downstream (FastAPI's own request validation and
# error-response serialization, which recurse over the same parsed
# structure) starts running into recursion limits of its own — reproduced
# directly: a body nested deeply enough to defeat only this middleware's
# own (now-iterative) checks still crashed FastAPI's `jsonable_encoder`
# with an uncaught RecursionError while building the resulting 422
# response, since letting the request through is not the same as every
# downstream consumer being able to safely process it. Checked once here,
# independent of what this middleware itself does or doesn't recurse on.
MAX_JSON_NESTING_DEPTH = 20


def _exceeds_max_depth(value: object, max_depth: int = MAX_JSON_NESTING_DEPTH) -> bool:
    """True if `value` (already parsed by json.loads) nests a dict or list
    inside another more than `max_depth` times. Iterative — see
    `_contains_unpaired_surrogate`'s own docstring for why a JSON-shaped
    walk in this file must never be recursive.
    """
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return True
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current)
    return False


def _contains_unpaired_surrogate(value: object) -> bool:
    """Walks a JSON-decoded value looking for a string containing a lone
    UTF-16 surrogate. `json.loads` happily turns the escape `"\\ud800"`
    into a `str` holding the real U+D800 code point — the escape itself is
    ordinary ASCII on the wire, so this can only be caught by inspecting
    the *parsed* values, not the raw request bytes (those already
    round-trip through UTF-8 without error, and finding the same answer
    from the raw text would mean reimplementing JSON's own string-escape
    and key/value grammar by hand, just to re-derive what `json.loads`
    already computed correctly).

    Checks dict *keys* too, not just values: `json.loads(b'{"\\ud800": "x"}')`
    produces a dict keyed on the lone surrogate just as readily as it
    would as a value. A key-only gap here is not academic — it reaches the
    exact crash this middleware exists to prevent: a body missing required
    fields (say, `{"\\ud800": "x"}` posted to a route expecting `email`/
    `password`) sails through this check untouched, FastAPI's own 422
    handler then echoes the whole dict back as `input` in its validation-
    error detail, and serializing *that* response is what raises
    UnicodeEncodeError uncaught — reproduced directly.

    Iterative (an explicit stack), not recursive: a JSON body nested only
    ~500 levels deep — well under a kilobyte on the wire, and nowhere near
    MAX_INSPECTED_BODY_BYTES — crashed a straightforwardly recursive
    version of this walk with an uncaught RecursionError, reproduced
    directly. `json.loads` itself tolerated considerably deeper nesting
    (didn't fail until several thousand levels, measured directly) than
    that recursive walk did, since the walk added its own stack frames on
    top of whatever `json.loads` had already used — so it was the more
    exposed surface of the two, not `json.loads`. An explicit stack has no
    such limit; only memory bounds how deep it can go, and
    MAX_INSPECTED_BODY_BYTES already bounds the body this operates on.
    """
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeEncodeError:
                return True
        elif isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return False


class RejectUnpairedSurrogatesMiddleware:
    """Rejects any JSON request body containing a lone UTF-16 surrogate
    (e.g. the escape `"\\ud800"` with no matching low surrogate) before it
    reaches Pydantic or any route handler.

    A lone surrogate is not valid Unicode text — only a *pair* of them
    represents a real (astral-plane) character — but `json.loads` accepts
    the escape anyway and produces a `str` that crashes the first time
    anything tries to encode it as UTF-8. That happens in more places than
    any single field validator can guard: bcrypt hashing
    (`_reject_password_over_bcrypt_limit`, `core.security`), the SQL
    driver (a bound parameter reaching `cursor.execute` — a bare `email`
    field with no bcrypt validator at all crashes identically, deep inside
    aiosqlite), and even FastAPI's own default 422-validation-error
    handler, which echoes the rejected value back into its JSON response
    body and then fails to serialize *that*. A per-field fix closes
    exactly one of these; this middleware closes all of them by refusing
    the request before any of that code runs.

    A plain ASGI callable, not `starlette.middleware.base.BaseHTTPMiddleware`:
    that class runs the wrapped application in a separate anyio task
    communicating over a memory stream, which shifts exactly when control
    yields back to the event loop relative to the direct-ASGI baseline —
    reproduced directly as a real regression here, not a theoretical
    concern. `dispatch_admin_action`'s detached background task and the
    request's own handling of the SAME reset_password call share one
    `AsyncSession` in `TestAdminResetPassword`'s test fixtures (by design,
    to catch exactly this class of bug in application code — see that
    fixture's own docstring); routing through BaseHTTPMiddleware's extra
    task boundary was enough to change the interleaving and made 20+ of
    those tests fail with SQLAlchemy's "session is provisioning a new
    connection; concurrent operations are not permitted". A pure ASGI
    middleware — buffer `receive`'s body messages, check them, replay them
    to the app through a wrapped `receive` — runs the downstream app in
    the exact same task as this middleware, matching the no-middleware
    baseline's scheduling exactly. Verified: the full backend suite is
    clean with this implementation, and reproducibly broken with the
    BaseHTTPMiddleware version.

    Parses the body itself (rather than relying on each route's own
    Pydantic model to do so) since the check must run before ANY
    downstream code — including the model parsing that would otherwise be
    the first thing to touch the string. A body that isn't valid JSON at
    all is let through unchanged; the route's own parsing reports that
    error exactly as it does today. Every endpoint in this app is JSON;
    there is no file-upload/multipart path to special-case.

    Two bounds keep this buffering from becoming its own vulnerability,
    given it necessarily runs before authentication (every check above
    must run before ANY downstream code, auth included — an unauthenticated
    client reaches this middleware on every request):

    - Only requests whose Content-Type FastAPI itself would parse as JSON
      are buffered at all (`_is_json_content_type` — `application/json` or
      any `application/*+json` subtype, matching `routing.py`'s own
      `strict_content_type=True` check exactly, the default and
      unoverridden default for every route here) — a GET's absent body, a
      webhook on a different content type, or a route this app doesn't
      even define, all skip the buffer-then-replay path entirely rather
      than paying its cost for no benefit. Matching only the literal
      `application/json` string missed every `+json` subtype
      (`application/problem+json` and similar) that FastAPI still parses
      and dispatches as JSON — reproduced directly as a real bypass of
      the Unicode check below.
    - `MAX_INSPECTED_BODY_BYTES` (or `MAX_INGEST_BODY_BYTES` for the
      scan-ingest paths in `_LARGE_PAYLOAD_PATHS`) caps the running total
      as chunks arrive, not the `Content-Length` header (which a client
      controls and can lie about, or omit entirely under chunked transfer
      encoding) — a client sending a large or indefinitely-streamed body
      is rejected with 413 as soon as the running total crosses the
      limit, before the chunk that crossed it is even appended to the
      buffer.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Only a body FastAPI itself will parse as JSON can ever contain
        # the escape this middleware looks for — a GET's absent body, or
        # any content type FastAPI won't treat as JSON, can't. Checked
        # BEFORE any buffering: every request otherwise ran through the
        # buffer-then-replay dance below regardless of route or method,
        # unauthenticated, for no benefit — a GET, a webhook with a
        # different content type, or any route this app doesn't even
        # define all paid the same buffering cost as a real JSON POST.
        #
        # Read via Starlette's own Headers(scope=scope) rather than
        # dict(scope["headers"]) — a raw dict built from the ASGI header
        # list keeps whichever duplicate came LAST, but Headers.get() (what
        # request.headers.get("content-type") uses internally, at
        # routing.py's own JSON-detection call site) keeps the FIRST.
        # These disagree on a request carrying two Content-Type headers
        # (`application/json` first, `text/plain` second — a client is
        # free to send this; nothing rejects it upstream): the dict-based
        # read here saw `text/plain` and skipped inspection entirely,
        # while FastAPI's own header read saw `application/json` and
        # parsed + dispatched the body as JSON anyway — a genuine bypass
        # of both the Unicode check and the size limit below, reproduced
        # directly as the same uncaught UnicodeEncodeError this middleware
        # exists to prevent.
        content_type_header = Headers(scope=scope).get("content-type", "")
        if not _is_json_content_type(content_type_header):
            await self.app(scope, receive, send)
            return

        # Buffer every body chunk before deciding anything — a request can
        # split its body across multiple ASGI messages, and the check needs
        # the whole thing to call json.loads at all. Collected into a list
        # and joined once at the end, not concatenated with += per chunk:
        # bytes is immutable, so `body += chunk` in a loop reallocates and
        # copies the *entire* accumulated buffer on every iteration — O(n²)
        # in total body size for a request split into many small ASGI
        # chunks (a slow-drip client, or ordinary chunked transfer
        # encoding, can trigger this trivially).
        #
        # The limit itself is checked as each chunk arrives rather than
        # after the fact — a request whose Content-Length lies (or is
        # absent, under chunked transfer encoding) would otherwise still
        # buffer without limit purely by sending enough `more_body=True`
        # messages. This middleware runs before authentication (it must —
        # the checks below have to run before ANY downstream code, auth
        # included), so an unauthenticated client sending a large or
        # indefinitely-streamed body is exactly who this bounds: rejected
        # as soon as the running total crosses the limit, before appending
        # the chunk that crossed it, rather than after materializing the
        # whole oversized body first. Scan-ingest routes get the higher
        # ceiling (see MAX_INGEST_BODY_BYTES's own comment) — matched on
        # `scope["path"]` since route resolution hasn't happened yet at
        # this point in the ASGI pipeline.
        max_body_bytes = (
            MAX_INGEST_BODY_BYTES if scope.get("path") in _LARGE_PAYLOAD_PATHS
            else MAX_INSPECTED_BODY_BYTES
        )
        body_chunks: list[bytes] = []
        messages: list[Message] = []
        total_bytes = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                # A disconnect or other non-body message ends buffering;
                # replay whatever was collected and let the app handle it.
                messages.append(message)
                break
            chunk = message.get("body", b"")
            total_bytes += len(chunk)
            if total_bytes > max_body_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large."},
                )
                await response(scope, receive, send)
                return
            messages.append(message)
            body_chunks.append(chunk)
            more_body = message.get("more_body", False)
        body = b"".join(body_chunks)

        if body:
            # json.loads itself is a recursive-descent parser (its C
            # implementation included) and can raise RecursionError on a
            # deeply nested body — not a subclass of json.JSONDecodeError,
            # so it needs its own clause here. Reachable well inside
            # MAX_INSPECTED_BODY_BYTES: measured directly, json.loads only
            # started failing somewhere between 5,000 and 10,000 levels of
            # nesting — a body in the tens of KB, not the 1 MiB limit.
            # Caught the same way a JSONDecodeError is: with a clean 400,
            # not an uncaught 500 (or worse — a RecursionError typically
            # leaves little of the interpreter's stack headroom free,
            # which risks the exception-handling and response-
            # serialization path immediately following it, unlike an
            # ordinary exception).
            try:
                parsed = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                parsed = None
            except RecursionError:
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Request body is nested too deeply."},
                )
                await response(scope, receive, send)
                return
            # Rejected here regardless of whether json.loads or this
            # middleware's own (now-iterative — see _contains_unpaired_
            # surrogate's docstring) checks can handle the nesting:
            # FastAPI's own request validation and error-response
            # serialization (jsonable_encoder, invoked when echoing a
            # rejected value back in a 422's detail) still recurse over
            # the same parsed structure and crash with an uncaught
            # RecursionError on a body deep enough to defeat only this
            # middleware's own defenses — reproduced directly. Checked
            # once here, before any downstream code (this middleware's own
            # unpaired-surrogate check included) ever sees the value.
            if parsed is not None and _exceeds_max_depth(parsed):
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Request body is nested too deeply."},
                )
                await response(scope, receive, send)
                return
            if parsed is not None and _contains_unpaired_surrogate(parsed):
                response = JSONResponse(
                    status_code=400,
                    content={"detail": "Request body contains invalid Unicode text."},
                )
                await response(scope, receive, send)
                return

        # Replay the buffered messages to the real app exactly as they
        # were received, so downstream body-reading code (FastAPI's own
        # request.body()/request.json() included) sees the identical byte
        # stream it would have without this middleware in front of it.
        replay = iter(messages)

        async def receive_buffered() -> Message:
            try:
                return next(replay)
            except StopIteration:
                return await receive()

        await self.app(scope, receive_buffered, send)
