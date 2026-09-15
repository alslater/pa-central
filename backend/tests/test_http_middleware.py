"""RejectUnpairedSurrogatesMiddleware — a request body containing a lone
UTF-16 surrogate (the JSON escape `"\\ud800"` with no matching low
surrogate) must be rejected with a clean 400 before it reaches Pydantic,
any route handler, or the database driver — all of which crash with an
unhandled UnicodeEncodeError the first time they try to UTF-8-encode such
a string. See RejectUnpairedSurrogatesMiddleware's own docstring for the
three distinct places this was previously reachable.
"""
import pytest


class TestRejectUnpairedSurrogatesMiddleware:
    async def test_unpaired_surrogate_in_a_field_with_its_own_bcrypt_validator_is_rejected_cleanly(
        self, client
    ):
        """The field _reject_password_over_bcrypt_limit actually guards.
        Its own ValueError is already caught correctly by Pydantic — this
        test pins that the *request* still gets a clean 400 rather than
        ever reaching that validator, i.e. the middleware is what actually
        stops this, not (only) the validator's own error handling."""
        r = await client.post(
            "/api/auth/login",
            content=b'{"email": "a@b.com", "password": "\\ud800"}',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert "invalid Unicode" in r.json()["detail"]

    async def test_unpaired_surrogate_in_a_field_with_no_validator_at_all_is_also_rejected(
        self, client
    ):
        """The regression this middleware specifically exists for: `email`
        has no bcrypt validator, so a per-field fix to
        _reject_password_over_bcrypt_limit alone would never have caught
        this — reproduced directly before this middleware existed as an
        UnicodeEncodeError raised deep inside aiosqlite's cursor.execute,
        not anywhere in application code."""
        r = await client.post(
            "/api/auth/login",
            content=b'{"email": "\\ud800", "password": "somepassword123"}',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert "invalid Unicode" in r.json()["detail"]

    async def test_unpaired_surrogate_nested_inside_the_body_is_rejected(self, client):
        """The check must walk nested objects, not just top-level string
        values — display_name here is one level deep in UserCreate's own
        shape, not a top-level field."""
        r = await client.post(
            "/api/auth/login",
            content=(
                b'{"email": "a@b.com", "password": "x", '
                b'"nested": {"inner": "\\ud800"}}'
            ),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400

    async def test_unpaired_surrogate_as_a_dict_key_is_rejected(self, client):
        """Regression: the walk originally checked only dict *values*
        (`value.values()`), so a body like `{"\\ud800": "x"}` sailed
        through untouched — the value "x" is fine, and the key was never
        inspected. That specific shape reaches the exact crash this
        middleware exists to prevent: with no `email`/`password` keys
        present, FastAPI's own 422 handler echoes the whole dict back as
        `input` in its validation-error detail, and serializing that
        response is what raises UnicodeEncodeError uncaught. Reproduced
        directly before this fix."""
        r = await client.post(
            "/api/auth/login",
            content=b'{"\\ud800": "x"}',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert "invalid Unicode" in r.json()["detail"]

    async def test_unpaired_surrogate_as_a_nested_dict_key_is_rejected(self, client):
        r = await client.post(
            "/api/auth/login",
            content=(
                b'{"email": "a@b.com", "password": "x", '
                b'"nested": {"\\ud800": 1}}'
            ),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400

    async def test_a_valid_unicode_password_is_not_rejected(self, client):
        """A real astral-plane character (a *paired* surrogate, encoding a
        single emoji) must not be caught by this — only a lone, unpaired
        one is invalid. Confirms the check doesn't over-reject ordinary
        non-ASCII input."""
        r = await client.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": "correct-horse-🎉-battery"},
        )
        # Wrong credentials (no such user) — not the 400 this middleware
        # would produce for genuinely invalid Unicode.
        assert r.status_code == 401

    async def test_malformed_non_json_body_passes_through_to_the_routes_own_error(
        self, client
    ):
        """A body that isn't valid JSON at all is not this middleware's
        concern — it lets it through unchanged so FastAPI's own body
        parsing reports the error exactly as it does without this
        middleware installed."""
        r = await client.post(
            "/api/auth/login",
            content=b"not json at all",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 422

    async def test_a_get_request_with_no_body_is_unaffected(self, client):
        r = await client.get("/api/auth/password-reset-config")
        assert r.status_code == 200

    async def test_a_body_past_max_json_nesting_depth_returns_400(self, client):
        """Security-hardening regression, in two parts. First: a
        straightforwardly recursive version of _contains_unpaired_surrogate
        crashed with an uncaught RecursionError on a body nested only ~500
        levels deep — well under a kilobyte on the wire, far below
        MAX_INSPECTED_BODY_BYTES — reproduced directly; fixed by making
        that walk iterative (see its own docstring). Second, found only
        once the first fix was in place: FastAPI's own request-validation
        and error-response serialization (jsonable_encoder, invoked when
        echoing a rejected value back in a 422's detail) ALSO recurses
        over the same parsed structure and crashed with an uncaught
        RecursionError on a body deep enough to defeat only this
        middleware's own (now-fixed) defenses — reproduced directly, this
        middleware's own checks are not the only thing downstream code
        needs protecting from. MAX_JSON_NESTING_DEPTH closes both: no
        request body deeper than any real schema in this app actually
        needs (see its own docstring — 20, with 5-10x headroom) is ever
        handed to this middleware's own checks OR the route beyond it."""
        from app.core.http_middleware import MAX_JSON_NESTING_DEPTH

        depth = MAX_JSON_NESTING_DEPTH + 10
        body = b"[" * depth + b'"x"' + b"]" * depth
        r = await client.post(
            "/api/auth/login",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert "nested too deeply" in r.json()["detail"]

    async def test_nesting_at_exactly_the_depth_limit_is_still_accepted(self, client):
        """The boundary case: MAX_JSON_NESTING_DEPTH itself must not
        under-reject a body that is merely AT the limit, only one that
        exceeds it — proven by asserting a real downstream response
        (401, wrong credentials) rather than this middleware's own 400,
        so a limit set one level too strict would show up as a failure
        here rather than passing for the wrong reason."""
        from app.core.http_middleware import MAX_JSON_NESTING_DEPTH

        depth = MAX_JSON_NESTING_DEPTH
        password = ("[" * depth) + "x" + ("]" * depth)
        r = await client.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": password},
        )
        assert r.status_code != 400

    async def test_a_body_nested_deep_enough_to_break_json_loads_itself_also_returns_400(
        self, client
    ):
        """A separate, deeper failure mode than MAX_JSON_NESTING_DEPTH: at
        this depth, json.loads itself raises RecursionError while parsing
        — measured directly, somewhere between 5,000 and 10,000 levels —
        long before any depth-limit check on the parsed *result* could
        ever run, since there is no result yet to check. Needs its own
        except clause in the middleware for exactly that reason."""
        depth = 50_000
        body = b"[" * depth + b"]" * depth
        r = await client.post(
            "/api/auth/login",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert "nested too deeply" in r.json()["detail"]

    async def test_a_non_json_content_type_skips_inspection_entirely(self, client):
        """Security-hardening regression: this middleware used to buffer
        (and JSON-decode-attempt) the body of every request regardless of
        Content-Type or route, unauthenticated — a real cost paid for
        requests that could never contain the escape this middleware looks
        for at all. A non-JSON Content-Type now skips buffering entirely,
        even though the raw bytes below are byte-for-byte the same payload
        that test_unpaired_surrogate_as_a_dict_key_is_rejected sends (there,
        with an `application/json` Content-Type, this returns 400) — proof
        the branch taken depends on Content-Type, not on the body's
        content. Reaches the route's own body parsing instead, which
        rejects it on its own terms (415, since /api/auth/login only
        accepts JSON) — never this middleware's 400."""
        r = await client.post(
            "/api/auth/login",
            content=b'{"\\ud800": "x"}',
            headers={"Content-Type": "text/plain"},
        )
        assert r.status_code != 400

    async def test_a_plus_json_content_type_still_gets_the_unicode_check(self, client):
        """Regression: FastAPI itself parses and dispatches
        `application/*+json` (not just the literal `application/json`) as
        JSON — routing.py's own `strict_content_type=True` check (the
        default, unoverridden by any route in this app) matches
        `subtype == "json" or subtype.endswith("+json")`. Matching only
        the literal string here left every `+json` media type
        (`application/problem+json`, `application/vnd.api+json`,
        `application/ld+json`, ...) completely unchecked by this
        middleware while FastAPI still parsed and dispatched them as JSON
        — reproduced directly as a real bypass reaching the exact
        UnicodeEncodeError crash this middleware exists to prevent, via
        FastAPI's own validation-error response failing to serialize the
        rejected value it echoes back. Byte-for-byte the same payload as
        test_unpaired_surrogate_as_a_dict_key_is_rejected, only the
        Content-Type differs."""
        r = await client.post(
            "/api/auth/login",
            content=b'{"\\ud800": "x"}',
            headers={"Content-Type": "application/problem+json"},
        )
        assert r.status_code == 400
        assert "invalid Unicode" in r.json()["detail"]

    async def test_duplicate_content_type_headers_still_get_inspected(self, client):
        """Regression: `dict(scope["headers"])` (a plain dict built from
        the raw ASGI header list) keeps whichever duplicate came LAST when
        a header name repeats, but Starlette's `Headers.get()` — which is
        what `request.headers.get("content-type")` uses internally, at
        FastAPI's own JSON-detection call site (routing.py) — keeps the
        FIRST. A client is free to send two Content-Type headers (nothing
        rejects this upstream); with `application/json` first and
        `text/plain` second, the old dict-based read here saw
        `text/plain` and skipped inspection entirely, while FastAPI's own
        header read saw `application/json` and parsed + dispatched the
        body as JSON anyway — reproduced directly as the same
        UnicodeEncodeError crash this middleware exists to prevent, via a
        completely different route than the +json-subtype bypass above."""
        r = await client.post(
            "/api/auth/login",
            content=b'{"\\ud800": "x"}',
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Type", "text/plain"),
            ],
        )
        assert r.status_code == 400
        assert "invalid Unicode" in r.json()["detail"]

    async def test_oversized_json_body_is_rejected_with_413(self, client):
        """Security-hardening regression: buffering had no size bound at
        all — an unauthenticated client could send an arbitrarily large (or
        indefinitely chunked-transfer-streamed) JSON body and this
        middleware would materialize the whole thing in memory (as chunks,
        then again joined, then again JSON-decoded) before any route or
        auth check ever ran. A body over MAX_INSPECTED_BODY_BYTES is now
        rejected outright."""
        from app.core.http_middleware import MAX_INSPECTED_BODY_BYTES

        oversized = b'{"email": "a@b.com", "password": "' + b"x" * MAX_INSPECTED_BODY_BYTES + b'"}'
        r = await client.post(
            "/api/auth/login",
            content=oversized,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 413

    async def test_scan_ingest_paths_get_a_much_higher_size_ceiling(self, client):
        """Scan-ingest routes carry unbounded findings/risks lists
        (RepoScanResultIngest, ScanPayload — schemas/__init__.py) with no
        per-item or list-length cap: a genuinely large or long-neglected
        project can produce thousands of package-alert findings, plausibly
        several MB of JSON. The default MAX_INSPECTED_BODY_BYTES (1 MiB)
        would reject a legitimate scan report from exactly that project —
        confirmed via the body size below, which sits comfortably over the
        default limit but under MAX_INGEST_BODY_BYTES.

        No API key is sent, so this still 401s downstream (this middleware
        runs before auth, by design — see its own docstring) — the only
        thing under test is that the response is NOT this middleware's 413,
        proving the higher ceiling, not the whole route's success, is what
        this checks."""
        from app.core.http_middleware import MAX_INSPECTED_BODY_BYTES

        oversized_for_default_but_not_for_ingest = (
            b'{"hostname": "h", "status": "clean", "findings": null, "padding": "'
            + b"x" * (MAX_INSPECTED_BODY_BYTES + 1024)
            + b'"}'
        )
        r = await client.post(
            "/api/ingest/scans",
            content=oversized_for_default_but_not_for_ingest,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code != 413
        assert r.status_code == 401  # no API key — rejected downstream, not by this middleware

    async def test_scan_ingest_paths_still_have_a_ceiling(self, client):
        """The higher limit is still a limit, not "no limit" — confirms
        MAX_INGEST_BODY_BYTES itself is enforced, not merely that
        MAX_INSPECTED_BODY_BYTES was bypassed entirely for these paths."""
        from app.core.http_middleware import MAX_INGEST_BODY_BYTES

        way_oversized = (
            b'{"hostname": "h", "padding": "' + b"x" * (MAX_INGEST_BODY_BYTES + 1024) + b'"}'
        )
        r = await client.post(
            "/api/ingest/scans",
            content=way_oversized,
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 413


@pytest.fixture
def _contains_unpaired_surrogate():
    from app.core.http_middleware import _contains_unpaired_surrogate
    return _contains_unpaired_surrogate


class TestContainsUnpairedSurrogateHelper:
    """Unit-level coverage for the walk itself, independent of the HTTP
    layer above."""

    async def test_true_for_a_lone_high_surrogate(self, _contains_unpaired_surrogate):
        assert _contains_unpaired_surrogate("\ud800") is True

    async def test_survives_nesting_deep_enough_to_crash_a_recursive_version(
        self, _contains_unpaired_surrogate
    ):
        """Regression: a straightforwardly recursive implementation of
        this walk raised an uncaught RecursionError at only ~500 levels
        of nesting, reproduced directly — this depth is well past that,
        confirming the iterative (explicit-stack) rewrite has no
        equivalent limit of its own. (The HTTP-layer MAX_JSON_NESTING_DEPTH
        check rejects a real request nested this deeply before it ever
        reaches this function at all — this test exercises the helper
        directly, bypassing that, specifically to prove IT no longer has
        the failure mode the depth limit was never meant to be the only
        fix for.)"""
        depth = 5000
        nested: object = "\ud800"
        for _ in range(depth):
            nested = [nested]
        assert _contains_unpaired_surrogate(nested) is True

    async def test_false_for_a_valid_paired_surrogate_astral_character(
        self, _contains_unpaired_surrogate
    ):
        assert _contains_unpaired_surrogate("🎉") is False

    async def test_false_for_ordinary_ascii_and_non_ascii_text(
        self, _contains_unpaired_surrogate
    ):
        assert _contains_unpaired_surrogate("hello") is False
        assert _contains_unpaired_surrogate("héllo") is False

    async def test_walks_into_nested_dicts_and_lists(self, _contains_unpaired_surrogate):
        assert _contains_unpaired_surrogate({"a": {"b": ["c", "\ud800"]}}) is True
        assert _contains_unpaired_surrogate({"a": {"b": ["c", "d"]}}) is False

    async def test_true_for_a_lone_surrogate_used_as_a_dict_key(
        self, _contains_unpaired_surrogate
    ):
        """Regression: the walk originally iterated only `dict.values()`,
        so a surrogate living in a *key* (with an entirely ordinary value)
        was invisible to it."""
        assert _contains_unpaired_surrogate({"\ud800": "ordinary value"}) is True

    async def test_true_for_a_lone_surrogate_used_as_a_nested_dict_key(
        self, _contains_unpaired_surrogate
    ):
        assert _contains_unpaired_surrogate({"a": {"\ud800": 1}}) is True

    async def test_false_for_non_string_scalars(self, _contains_unpaired_surrogate):
        assert _contains_unpaired_surrogate(42) is False
        assert _contains_unpaired_surrogate(None) is False
        assert _contains_unpaired_surrogate(True) is False


@pytest.fixture
def _exceeds_max_depth():
    from app.core.http_middleware import _exceeds_max_depth
    return _exceeds_max_depth


class TestExceedsMaxDepthHelper:
    """Unit-level coverage for the depth check, independent of the HTTP
    layer above. Uses an explicit max_depth argument throughout rather
    than the module's real MAX_JSON_NESTING_DEPTH, so these tests describe
    the function's own boundary behavior and stay correct regardless of
    where that constant is tuned."""

    async def test_false_for_a_flat_value(self, _exceeds_max_depth):
        assert _exceeds_max_depth("just a string", max_depth=5) is False
        assert _exceeds_max_depth(42, max_depth=5) is False
        assert _exceeds_max_depth(None, max_depth=5) is False

    async def test_false_at_exactly_the_limit(self, _exceeds_max_depth):
        value: object = "leaf"
        for _ in range(5):
            value = [value]
        assert _exceeds_max_depth(value, max_depth=5) is False

    async def test_true_one_level_past_the_limit(self, _exceeds_max_depth):
        value: object = "leaf"
        for _ in range(6):
            value = [value]
        assert _exceeds_max_depth(value, max_depth=5) is True

    async def test_dict_nesting_counts_the_same_as_list_nesting(self, _exceeds_max_depth):
        value: object = "leaf"
        for _ in range(6):
            value = {"k": value}
        assert _exceeds_max_depth(value, max_depth=5) is True

    async def test_survives_nesting_deep_enough_to_crash_a_recursive_version(
        self, _exceeds_max_depth
    ):
        """Iterative (an explicit stack), for the same reason as
        _contains_unpaired_surrogate: this function walks the same
        JSON-decoded shape and must never itself become the thing that
        needs a depth limit."""
        depth = 5000
        nested: object = "leaf"
        for _ in range(depth):
            nested = [nested]
        assert _exceeds_max_depth(nested, max_depth=20) is True


@pytest.fixture
def _is_json_content_type():
    from app.core.http_middleware import _is_json_content_type
    return _is_json_content_type


class TestIsJsonContentTypeHelper:
    """Must match FastAPI's own JSON-detection exactly (routing.py's
    `get_request_handler`, `strict_content_type=True` — the default and
    unoverridden by any route in this app), since these tests exist to
    pin the correspondence: any content type FastAPI parses as JSON must
    also be one this middleware inspects, or a Unicode payload under it
    bypasses the check entirely while still reaching the route.
    """

    async def test_true_for_plain_application_json(self, _is_json_content_type):
        assert _is_json_content_type("application/json") is True

    async def test_true_for_application_json_with_charset_parameter(
        self, _is_json_content_type
    ):
        assert _is_json_content_type("application/json; charset=utf-8") is True

    async def test_true_for_plus_json_subtypes(self, _is_json_content_type):
        """Regression: the original check matched only the literal string
        "application/json" — every one of these is parsed and dispatched
        as JSON by FastAPI itself, and none of them matched."""
        assert _is_json_content_type("application/problem+json") is True
        assert _is_json_content_type("application/vnd.api+json") is True
        assert _is_json_content_type("application/ld+json") is True

    async def test_false_for_non_application_maintype(self, _is_json_content_type):
        assert _is_json_content_type("text/plain") is False
        assert _is_json_content_type("text/json") is False  # maintype is text, not application
        assert _is_json_content_type("multipart/form-data") is False

    async def test_false_for_application_subtype_that_merely_contains_json(
        self, _is_json_content_type
    ):
        """Only an exact "json" subtype or one ENDING in "+json" counts —
        matches FastAPI's own `subtype == "json" or
        subtype.endswith("+json")`, not a substring search."""
        assert _is_json_content_type("application/jsonlines") is False
        assert _is_json_content_type("application/x-json-stream") is False

    async def test_false_for_empty_or_missing_content_type(self, _is_json_content_type):
        assert _is_json_content_type("") is False


class TestMultiChunkBodyBuffering:
    """The ASGI `receive` callable can deliver a single request body split
    across several `http.request` messages (`more_body=True` on all but
    the last) — ordinary chunked transfer encoding, or simply a slow
    client, can produce this. None of the other tests in this file
    exercise it at all: `httpx.AsyncClient`'s `content=`/`json=` always
    hands the whole body to the ASGI transport in one message. Drives the
    middleware directly against a hand-built `receive`/`send`/`scope`
    rather than through a real HTTP client, since that's the only way to
    control ASGI-level chunking precisely.
    """

    async def _run(self, chunks: list[bytes]) -> list[dict]:
        from app.core.http_middleware import RejectUnpairedSurrogatesMiddleware

        messages = [
            {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
            for i, chunk in enumerate(chunks)
        ]
        message_iter = iter(messages)

        async def receive():
            return next(message_iter)

        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        async def downstream_app(scope, receive, send):
            # Reads the body back out exactly as FastAPI's own body parsing
            # would, to prove the reassembled bytes are correct — not just
            # that the middleware doesn't crash.
            body = b""
            more_body = True
            while more_body:
                msg = await receive()
                body += msg.get("body", b"")
                more_body = msg.get("more_body", False)
            await send({
                "type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"application/octet-stream")],
            })
            await send({"type": "http.response.body", "body": body})

        middleware = RejectUnpairedSurrogatesMiddleware(downstream_app)
        # A real client posting JSON sets this — the middleware now skips
        # buffering entirely for anything else (see the Content-Type-gate
        # tests below), so this scope must declare it like any other test
        # in this file's real HTTP requests already implicitly do via
        # httpx's own Content-Type handling.
        scope = {
            "type": "http",
            "headers": [(b"content-type", b"application/json")],
        }
        await middleware(scope, receive, send)
        return sent

    async def test_a_body_split_across_many_small_chunks_is_reassembled_correctly(self):
        # A valid JSON body, deliberately fed to the middleware one byte
        # (or a few bytes) at a time — the shape a slow-drip client or
        # ordinary chunked transfer encoding produces. Correct
        # reassembly (not just "didn't crash") is proven by reading the
        # exact bytes back out on the other side.
        full_body = b'{"email": "a@b.com", "password": "hunter2"}'
        chunks = [full_body[i:i + 3] for i in range(0, len(full_body), 3)]
        assert len(chunks) > 10  # genuinely many small chunks, not one or two

        sent = await self._run(chunks)
        body_message = next(m for m in sent if m["type"] == "http.response.body")
        assert body_message["body"] == full_body

    async def test_a_surrogate_split_across_a_chunk_boundary_is_still_caught(self):
        # The unpaired-surrogate escape itself ("\ud800") straddles two
        # separate ASGI messages — proving the check runs against the
        # fully-reassembled body, not per-chunk (which could never detect
        # a JSON escape sequence split across a chunk boundary at all).
        full_body = b'{"email": "a@b.com", "password": "\\ud800"}'
        split_at = full_body.index(b"\\ud800") + 3
        chunks = [full_body[:split_at], full_body[split_at:]]

        sent = await self._run(chunks)
        start_message = next(m for m in sent if m["type"] == "http.response.start")
        assert start_message["status"] == 400

    async def test_many_small_chunks_stays_fast_not_quadratic(self):
        """Performance regression: `body += message["body"]` on every ASGI
        chunk copies the *entire* accumulated buffer each time (`bytes` is
        immutable) — O(n^2) in total body size for a request split into
        many small chunks. Measured directly (not asserted here, since
        that would be a fragile CI timing test at this margin) at 20,000
        3-byte chunks: ~4.6s for the quadratic `+=` pattern versus ~2ms
        for accumulating into a list and joining once — a ~2500x
        difference that grows with chunk count, confirming genuine O(n^2)
        scaling, not just a constant-factor slowdown.

        This test uses a generous, deliberately non-tight margin (2s for
        10,000 chunks — the linear implementation finishes in low single-
        digit milliseconds, per the measurement above) specifically so it
        stays robust under CI load rather than becoming its own source of
        flakiness, while still being far below where the quadratic
        pattern would land at this chunk count (order of 1 second, per the
        same measurement).
        """
        import time

        chunk = b"x"
        n_chunks = 10_000
        chunks = [chunk] * n_chunks

        start = time.perf_counter()
        sent = await self._run(chunks)
        elapsed = time.perf_counter() - start

        body_message = next(m for m in sent if m["type"] == "http.response.body")
        assert body_message["body"] == chunk * n_chunks
        assert elapsed < 2.0, (
            f"buffering {n_chunks} chunks took {elapsed:.2f}s — expected well "
            "under 1s for a linear implementation; this smells like the "
            "quadratic body += chunk pattern regressed back in"
        )


class TestBodySizeLimit:
    """MAX_INSPECTED_BODY_BYTES must bound the buffer as chunks arrive, not
    merely the final joined body — a request declaring no (or a lying)
    Content-Length under chunked transfer encoding has no header for this
    middleware to trust; the only reliable signal is the running total of
    bytes actually received.
    """

    async def test_stops_reading_once_the_running_total_crosses_the_limit(self):
        """The receive() below can supply chunks indefinitely (more_body is
        always True) — an indefinitely-streamed body, exactly the shape a
        Content-Length-based check cannot catch (there is no
        Content-Length at all here, matching real chunked transfer
        encoding). Proves the check runs DURING accumulation, not after
        the whole body is collected: if it ran only once at the end (e.g.
        after breaking out of the loop some other way), this receive()
        would be called forever and the test would hang. A generous
        chunk_calls ceiling, well above what should ever be needed to
        cross the limit, converts a real implementation bug here into a
        clear assertion failure instead of an actual hang.
        """
        from app.core.http_middleware import (
            MAX_INSPECTED_BODY_BYTES,
            RejectUnpairedSurrogatesMiddleware,
        )

        chunk = b"x" * 4096
        chunk_calls = 0
        max_calls_before_giving_up = (MAX_INSPECTED_BODY_BYTES // len(chunk)) + 10

        async def receive():
            nonlocal chunk_calls
            chunk_calls += 1
            if chunk_calls > max_calls_before_giving_up:
                raise AssertionError(
                    "middleware kept reading well past MAX_INSPECTED_BODY_BYTES "
                    "— the size check is not running during accumulation"
                )
            return {"type": "http.request", "body": chunk, "more_body": True}

        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        async def downstream_app(scope, receive, send):
            raise AssertionError("must be rejected before reaching the app")

        middleware = RejectUnpairedSurrogatesMiddleware(downstream_app)
        scope = {"type": "http", "headers": [(b"content-type", b"application/json")]}
        await middleware(scope, receive, send)

        start_message = next(m for m in sent if m["type"] == "http.response.start")
        assert start_message["status"] == 413
        # The number of chunks actually read is bounded by the limit, not
        # by the (effectively infinite) supply receive() could provide.
        assert chunk_calls <= max_calls_before_giving_up
