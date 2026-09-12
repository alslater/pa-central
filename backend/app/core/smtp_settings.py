"""Shared loading of SMTP configuration from the SystemSetting table.

This logic was originally inlined in app.api.ingest._send_result_email. It is
extracted here because three separate call sites now need it — scan-result
notifications, the self-service password reset flow, and the admin-initiated
reset — and a divergence between them would mean one path silently failing to
send while another works.
"""
import ipaddress
import math
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.core.email import (
    DEFAULT_SMTP_TIMEOUT_SECONDS,
    MAX_SMTP_TIMEOUT_SECONDS,
    SmtpConfig,
)
from app.core.encryption import decrypt_value
from app.models import SettingValueType, SystemSetting, setting_is_true

# Non-numeric hostnames that only ever resolve on the machine running the
# server. IP-literal loopback/unspecified addresses are not listed here —
# they are rejected by parsing with ipaddress.ip_address() instead, since an
# exact-string set could only ever cover a few of the addresses in
# 127.0.0.0/8 (all of it is loopback, not just 127.0.0.1) and the many
# equivalent spellings of the IPv6 loopback/unspecified addresses. Reproduced
# directly: 127.0.0.2, 127.1.2.3, and ::0:0:0:0:0:0:1 all passed the old
# exact-string set in production.
_LOOPBACK_HOSTNAMES = frozenset({"localhost"})


def looks_like_public_url(value: str) -> bool:
    """True if `value` could plausibly address this deployment from outside.

    Deliberately shallow — it cannot know what is actually reachable, and is
    not trying to. It rejects the mistakes that produce a link nobody can use:
    a non-http(s) scheme, a missing host, an out-of-range or non-numeric port,
    a query string, fragment or non-root path (the reset-password path is
    appended after this value, and the frontend only routes that path at
    the root — see the path check below), or a loopback/unspecified
    address left over from development.

    **Loopback is allowed under DEBUG.** On a developer's machine the app
    genuinely is on localhost, so the link is correct there and rejecting it
    makes the feature untestable locally. DEBUG is already the flag this
    project uses for that distinction — config.py relaxes the
    insecure-defaults guard the same way — and it must never be set in
    production, where the check therefore still applies in full.

    **Plain HTTP is allowed under DEBUG only, for the same reason.** The
    reset token travels in the URL fragment specifically so it never
    reaches the network (see build_reset_url's docstring) — but that
    guarantee assumes the channel serving the page and the subsequent
    password-change POST is itself trustworthy. Over unencrypted HTTP it
    is not: an on-path attacker can rewrite the served JavaScript to read
    `window.location.hash` and exfiltrate the token, or capture the
    plaintext POST that carries the new password. Rejecting `http://`
    outside DEBUG closes that regardless of how the token itself is
    delivered; local development still needs it, since a developer's own
    machine has no such attacker on the path.

    **Loopback/unspecified IP literals are parsed, not string-matched.** An
    exact-string set (`{"127.0.0.1", "::1", "0.0.0.0"}`) only ever covers the
    handful of spellings someone thought to list — it missed the rest of
    `127.0.0.0/8` (all of it loopback, not just `.1`) and every non-canonical
    IPv6 form of the same addresses. Reproduced directly: `127.0.0.2`,
    `127.1.2.3`, and the fully-expanded `0:0:0:0:0:0:0:1` all passed as
    "public" in production. `ipaddress.ip_address()` classifies the address
    itself (`is_loopback`, `is_unspecified`) regardless of spelling; a
    non-numeric hostname like `localhost` isn't an IP literal at all, so it
    still needs its own small set.

    Shared between the write-time check in api/system_settings.py (rejects a
    PATCH before it is stored) and the read-time check in
    services/password_reset.py's require_app_base_url (rejects issuance
    against a value that reached storage some other way — restored from a
    backup, written directly, or set before this validation existed). A
    single definition, because the two checking different things for the
    same reason and drifting apart is exactly what let a non-empty but
    unusable URL (`ftp://host`, `https://host?next=x`) advertise the feature
    as enabled while every reset link it issued was broken.
    """
    try:
        parsed = urlparse(value)
        # `.port` is where urlparse actually validates the port — it parses
        # lazily, so urlparse() itself succeeds on "…:notaport" or "…:99999"
        # and only raises here. Touched inside the guard deliberately: without
        # it those values pass and produce links no browser can open.
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if parsed.scheme == "http" and not app_settings.debug:
        return False
    # urlparse does not validate the authority the way it validates the
    # port: it happily returns a non-empty, non-whitespace-trimmed
    # "hostname" for something no DNS resolution or browser navigation
    # could ever use. "https://not a url" parses to hostname="not a url" —
    # ipaddress.ip_address() then raises (not an IP literal), and the
    # fallback at the end of this function treats that exactly like an
    # ordinary hostname such as "pa.example.com", returning True. Reproduced
    # directly: socket.getaddrinfo("not a url", 443) fails with "Name or
    # service not known", so the value this function just called usable
    # cannot be reached by anything. On the admin-reset path specifically,
    # that failure is discovered only after the target's password has
    # already been invalidated — this function exists precisely to refuse
    # a knowable misconfiguration before that point, and a bare space is as
    # knowable as it gets.
    #
    # A hostname never legitimately contains whitespace or a C0/DEL control
    # character (RFC 3986's reg-name excludes them all; every case checked
    # against real deployments — plain ASCII, IDN/punycode, IPv4, bracketed
    # IPv6 — is untouched by this). str.isspace() also catches tab/newline,
    # even though urlparse silently strips *those* from the whole URL before
    # parsing (a separate WHATWG-alignment quirk) rather than leaving them in
    # the hostname — this check does not depend on which of the two happens
    # to apply to a given character.
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in parsed.hostname):
        return False
    # urlparse accepts port 0 (it is in range), but nothing can be reached
    # there — a link carrying it is as dead as one with a malformed port.
    if port == 0:
        return False
    # build_reset_url appends "/reset-password#token=…" to this value, so a
    # query string or fragment here lands *before* the path and produces a
    # structurally broken link ("…?next=/x/reset-password#token=…"). Rejected
    # rather than stripped: silently discarding part of what an admin typed
    # would be worse than telling them it is not usable.
    if parsed.query or parsed.fragment:
        return False
    # Same reasoning, for a non-root path component. build_reset_url appends
    # "/reset-password" directly onto the (rstrip('/')'d) value, so
    # "https://pa.example.com/settings" becomes
    # ".../settings/reset-password" — a syntactically valid URL that is not
    # this deployment's reset-password page. The frontend's router
    # registers "/reset-password" as a root-level route only (App.tsx); any
    # other path falls through its catch-all and redirects to "/", losing
    # the token fragment before ResetPassword.tsx ever mounts. Only "" (no
    # path at all) and "/" (a bare trailing slash, which rstrip('/') already
    # handles downstream) address the actual reset-password route; anything
    # else needs subpath-aware routing this frontend does not have.
    if parsed.path not in ("", "/"):
        return False
    hostname = parsed.hostname.lower()
    if hostname in _LOOPBACK_HOSTNAMES:
        return app_settings.debug
    try:
        # urlparse strips brackets from a bracketed IPv6 literal, so this is
        # exactly the string ipaddress.ip_address() expects — no bracket
        # handling needed here. Raises ValueError for an ordinary hostname
        # like "pa.example.com", which is the common case and not loopback.
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    if ip.is_loopback or ip.is_unspecified:
        return app_settings.debug
    return True


async def load_settings_map(session: AsyncSession) -> dict[str, str]:
    """All system settings as a flat {key: value} dict, secrets decrypted.

    A NULL value and a secret that fails to decrypt both collapse to "" so
    callers can use plain truthiness without distinguishing the two — neither
    is usable as a credential.
    """
    result = await session.execute(select(SystemSetting))
    settings_map: dict[str, str] = {}
    for s in result.scalars().all():
        if s.value is None:
            settings_map[s.key] = ""
        elif s.value_type == SettingValueType.secret:
            try:
                settings_map[s.key] = decrypt_value(s.value, app_settings.settings_encryption_key)
            except Exception:  # noqa: BLE001
                settings_map[s.key] = ""
        else:
            settings_map[s.key] = s.value
    return settings_map


#: The only values EmailService._send_sync (core/email.py) actually acts
#: on. "none" and anything else it doesn't recognise both fall through to
#: plain, unencrypted smtplib.SMTP with no starttls() upgrade — "none" is
#: the deliberate opt-out spelling this set exists to keep distinguishable
#: from a typo that means the same thing by accident (see
#: parse_smtp_tls_mode below).
VALID_SMTP_TLS_MODES = frozenset({"none", "ssl", "starttls"})


#: RFC 1035 §3.1 caps a full domain name at 255 octets; smtplib itself
#: enforces nothing, so a value beyond this is rejected here rather than
#: discovered as a DNS failure at send time.
MAX_SMTP_HOST_LENGTH = 255


def looks_like_smtp_host(value: str) -> bool:
    """True if `value` is a hostname or IP literal smtplib could plausibly
    connect to.

    Deliberately shallow, matching looks_like_public_url's own scope: this
    cannot know whether the host actually resolves or accepts connections,
    and is not trying to. It only rejects what is knowable in advance —
    empty, containing whitespace or a control character, or absurdly long —
    the same class of "syntactically impossible" value that currently
    passes build_smtp_config and self_service_reset_enabled untouched.

    `EmailService._send_sync` (core/email.py) passes cfg.host straight to
    `smtplib.SMTP(host, port)`, which calls `socket.getaddrinfo` — a value
    such as "not a host" or one containing a control character always fails
    that call with a predictable gaierror, but only once send is actually
    attempted, which happens after prepare_reset_email has already
    committed the reset token (see its own docstring on why: the link must
    be valid the moment sending is attempted) and, on the admin-initiated
    path (api/users.py's reset_password), after set_password has already
    invalidated the target's current password. Rejecting here — before any
    of that — turns a knowable misconfiguration into a 400 at settings-save
    time instead of a silent, unrecoverable failure discovered only when a
    real user next requests a reset.

    Not a full RFC 1123 hostname validator, for the same reason
    looks_like_public_url and parse_smtp_from_addr are not full validators
    for their own fields: the goal is to catch what is *already knowable* to
    be unusable, not to police every syntactic rule a real DNS label
    follows. A hostname with a leading hyphen or a doubled dot may well fail
    to resolve, but that failure is not knowable from the string alone the
    way whitespace, a control character, or emptiness is — those never
    resolve, on any network, under any configuration.
    """
    if not value or len(value) > MAX_SMTP_HOST_LENGTH:
        return False
    # Same reasoning and same check as looks_like_public_url's hostname
    # guard: a hostname never legitimately contains whitespace or a
    # C0/DEL control character, and socket.getaddrinfo raises on all of
    # them identically to an ordinary unresolvable name — the difference
    # is only that this is knowable before ever attempting the connection.
    return not any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def build_smtp_config(settings_map: dict[str, str]) -> SmtpConfig | None:
    """SmtpConfig from a settings map, or None when smtp_host is unset,
    smtp_port is not usable, smtp_tls_mode is not a recognised value, or
    smtp_from is not a usable header value.

    smtp_host is the single gate on whether email can be delivered at all —
    every other field has a usable default — so callers treat None as
    "email is not configured" rather than an error. smtp_port,
    smtp_tls_mode, and smtp_from are further, narrower gates for the same
    reason (see parse_smtp_port, parse_smtp_tls_mode, and
    parse_smtp_from_addr below).

    The host is stripped before use. Both the write-time gate
    (api/system_settings.py's `_effective`) and the read-time availability
    check (self_service_reset_enabled below) strip before deciding the
    value is present — so a value with leading/trailing whitespace (e.g.
    pasted from a UI field) passes both as valid, but was previously
    forwarded to smtplib untrimmed here. `socket.getaddrinfo(" host ", ...)`
    fails outright — a whitespace-padded host looks configured everywhere
    that checks presence, then fails DNS resolution during delivery. On the
    admin-reset path specifically, that failure is discovered only after
    the target's password has already been invalidated. Stripping here
    makes this the same value every consumer already agreed the setting
    represents, rather than reintroducing the difference at the one place
    that actually uses it over the network.
    """
    smtp_host = (settings_map.get("smtp_host") or "").strip()
    if not smtp_host or not looks_like_smtp_host(smtp_host):
        return None
    port = parse_smtp_port(settings_map.get("smtp_port"))
    if port is None:
        return None
    tls_mode = parse_smtp_tls_mode(settings_map.get("smtp_tls_mode"))
    if tls_mode is None:
        return None
    from_addr = parse_smtp_from_addr(settings_map.get("smtp_from"))
    if from_addr is None:
        return None
    return SmtpConfig(
        host=smtp_host,
        port=port,
        username=settings_map.get("smtp_username") or None,
        password=settings_map.get("smtp_password") or None,
        from_addr=from_addr,
        tls_mode=tls_mode,
        timeout=parse_smtp_timeout(settings_map.get("smtp_timeout_seconds")),
    )


def parse_smtp_tls_mode(raw: str | None) -> str | None:
    """One of VALID_SMTP_TLS_MODES, the "starttls" default, or None.

    `EmailService._send_sync` only recognises two exact strings — "ssl"
    selects `smtplib.SMTP_SSL`, and "starttls" calls `.starttls()` on a
    plain connection — and treats *anything else* (an unrecognised value,
    not just the deliberate "none") identically: plain, unencrypted
    `smtplib.SMTP` with no upgrade at all. This field is a plain string,
    not an enum, and (like smtp_port and smtp_timeout_seconds) PATCH
    accepted any value with no shape check at all — so a typo such as
    "start-tls" or a differently-cased "STARTTLS" silently sent password
    reset links, containing the raw credential, over an unencrypted
    connection to the SMTP server, with nothing anywhere recording that
    the admin's intended setting was never actually honoured. Reproduced
    directly: `_send_sync` with `tls_mode="start-tls"` used plain
    `smtplib.SMTP` and never called `.starttls()`, identically to an
    explicit "none".

    Returning None here — rather than silently falling back to "none" or
    the "starttls" default — means build_smtp_config treats an
    unrecognised value the same as an unusable host or port: "not
    configured," not "configured insecurely." A typo should not silently
    downgrade transport security; it should make the feature visibly
    unavailable instead, matching what self_service_reset_enabled already
    does for the other two narrow gates.

    Strips surrounding whitespace before comparing against
    VALID_SMTP_TLS_MODES: api/system_settings.py's PATCH-time
    effective-state check (_effective()) strips submitted and stored
    values alike before calling this function, so a stored " starttls "
    (trailing/leading whitespace from a legacy row, a direct edit, or a
    client that didn't trim) passed that gate while this function — called
    unstripped everywhere else (build_smtp_config,
    self_service_reset_enabled) — rejected the identical value outright.
    Enabling reset returned 200; the next read reported it unavailable.
    Normalizing here, once, keeps every caller agreeing without each
    needing to remember to strip first.
    """
    value = (raw or "").strip()
    if value == "":
        return "starttls"
    if value not in VALID_SMTP_TLS_MODES:
        return None
    return value


def parse_smtp_from_addr(raw: str | None) -> str | None:
    """A usable `From` header value, the "pa-central@localhost" default,
    or None.

    `build_password_reset_email` (core/email.py) assigns this straight to
    `EmailMessage()["From"]`. Python's own `email` module raises
    `ValueError` — not something this codebase's own error handling
    anywhere expects from that call — for a value containing a carriage
    return or line feed, since an unescaped CR/LF in a header value is a
    header-injection vector (a value like "pa\\r\\nBcc: attacker@evil.com"
    would inject an extra header). This field was previously stored and
    forwarded verbatim, with no shape check at all: PATCH accepted any
    string, and `prepare_reset_email` calls
    `EmailMessage()["From"] = from_addr` **after** the reset token has
    already been committed (see its own docstring on why: the link must be
    valid the moment sending is attempted). So a stored value containing
    CR/LF raised only once a real, active account triggered issuance —
    reproduced directly across all three callers:

    * `forgot_password` — the unknown-address path never reaches this
      code at all (it returns the padded 202 immediately), so the
      uncaught `ValueError` surfaced as an unhandled 500 only for a real
      account, an account-existence oracle by status code identical in
      shape to the `DBAPIError`-only lock-contention bug
      `prepare_reset_email`'s own docstring already describes — just via
      an exception type that guard does not catch.
    * `register()` (welcome links) — the new user row is already
      committed by this point, so the request rolls back with an
      unhandled 500 instead of the designed "roll back the account and
      report 502" path, leaving nothing behind but also giving the admin
      no informative response.
    * `reset_password` (admin-initiated) — `set_password` already ran and
      committed before `issue_reset_token` reaches this code, so the
      account's password is invalidated with an unhandled 500 in place of
      the designed 502, and no link was ever built to relay instead.

    Checked here, before any of prepare_reset_email's writes, for the
    identical reason smtp_host/smtp_port/smtp_tls_mode already are: a
    value this function can already tell is unusable must make the
    feature report itself unavailable, not fail destructively partway
    through issuance. Only CR/LF is rejected — this is deliberately not a
    full email-address-format validator (matching looks_like_public_url's
    own "deliberately shallow" scope for app_base_url): the one thing
    genuinely knowable in advance, and the one thing that actually raises,
    is the presence of characters `EmailMessage` itself refuses to accept
    in a header.
    """
    value = (raw or "").strip()
    if not value:
        return "pa-central@localhost"
    if "\r" in value or "\n" in value:
        return None
    return value


def parse_smtp_port(raw: str | None) -> int | None:
    """A usable TCP port (1-65535), the 587 default, or None.

    A bare `int(raw or "587")` raises ValueError on a non-numeric value —
    e.g. a legacy row, one restored from a backup, or written directly to
    the database. PATCH's own generic int check (api/system_settings.py's
    KEY_TYPES loop) only confirms the *submitted* value parses as an
    integer at all — smtp_port is in neither POSITIVE_INT_KEYS nor
    NON_NEGATIVE_INT_KEYS, so an out-of-range value like "99999" or "-1"
    passed that check untouched. A dedicated per-key check
    (`key == "smtp_port"`, in the same loop) now calls this function
    directly on the submitted value and rejects anything it returns
    `None` for, regardless of self_service_password_reset — needed
    because smtp_port is also read by the independent scan-result-
    notification path (api/ingest.py, build_smtp_config), which has
    nothing to do with that flag: before this check existed, an
    out-of-range port saved successfully while reset was off, and
    build_smtp_config then silently returned None for every subsequent
    scan-result email with no error surfaced anywhere. A bad value
    already stored from *before* this check existed is a separate
    concern the reset_enabled effective-value check further down still
    handles when enabling reset specifically. Unhandled, this function's
    own ValueError reached forgot_password only for a real,
    active account: an unknown address returns the padded 202 without ever
    calling build_smtp_config, so a raise here restored account enumeration
    by status code — the exact class of bug prepare_reset_email's own
    docstring says it exists to prevent, just via ValueError instead of the
    DBAPIError it already catches. On the admin-reset path
    (api/users.py's reset_password) the same raise surfaced only after
    set_password had already invalidated the account's current password,
    turning a config typo into an unrecoverable lockout instead of the
    designed 502 "the email could not be sent" response.

    Out-of-range values fail the same way a non-numeric one does: 0 and
    negative ports cannot be reached at all (the same reasoning
    looks_like_public_url applies to a URL's port), and smtplib's own
    socket connection raises OverflowError above 65535 — a failure that
    would surface exactly like the ValueError case if left unchecked here.
    """
    try:
        port = int((raw or "").strip() or "587")
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    return port


def smtp_timeout_is_usable(value: float) -> bool:
    """True if `value` is a timeout parse_smtp_timeout would actually honour
    rather than silently discard in favour of the default.

    Shared between parse_smtp_timeout (below) and api/system_settings.py's
    PATCH validator (the same pattern as parse_smtp_port and
    looks_like_public_url) — smtp_timeout_seconds is stored as a plain
    string, not SettingValueType.int, because it must accept decimals; the
    write path used to have no shape validation at all, so "abc", "0",
    "-5", "nan", or an overflowing literal like "1e309" all saved
    successfully while parse_smtp_timeout silently substituted the default
    at read time, leaving the admin looking at a value the runtime was
    never actually using. A single definition means the write-time gate and
    the read-time fallback can't drift on what "usable" means, the same
    reasoning as looks_like_public_url's own shared-definition note.

    Rejects, for the reasons detailed on parse_smtp_timeout:

    * non-positive — without a timeout smtplib blocks forever on a host
      that accepts and then goes quiet, holding an executor thread for the
      life of the process;
    * non-finite — `float("inf") > 0` is True, so "inf"/"Infinity" pass a
      bare positivity check; smtplib raises OverflowError on every send
      instead, and send_reset_email swallows exceptions, so the deployment
      would silently deliver no password reset emails at all. NaN is
      caught by the same check, since every comparison against it is
      False.
    * huge but finite — smtplib's OverflowError triggers on values well
      below where `math.isfinite` alone would stop objecting.
    """
    return math.isfinite(value) and 0 < value <= MAX_SMTP_TIMEOUT_SECONDS


def parse_smtp_timeout(raw: str | None) -> float:
    """A finite, positive float within socket.settimeout()'s usable range,
    or the default.

    See smtp_timeout_is_usable for what "usable" means and why an unusable
    value falls back rather than being honoured, and why write-time and
    read-time share that one definition.
    """
    try:
        value = float(raw or "")
    except (TypeError, ValueError):
        return DEFAULT_SMTP_TIMEOUT_SECONDS
    if not smtp_timeout_is_usable(value):
        return DEFAULT_SMTP_TIMEOUT_SECONDS
    return value


async def load_smtp_config(session: AsyncSession) -> SmtpConfig | None:
    """Convenience wrapper for callers that need only the SMTP config."""
    return build_smtp_config(await load_settings_map(session))


def self_service_reset_enabled(settings_map: dict[str, str]) -> bool:
    """True when the self-service password reset flow is available.

    Requires the explicit opt-in setting *and* everything a reset link needs:
    an SMTP host to send from, and a base URL to point at. An enabled flag
    alone is not enough — with either missing, no usable link can be built.

    The write path in api/system_settings.py already refuses to enable the
    setting without both. This re-checks at read time because a row can be
    cleared afterwards by something that write path does not control: a direct
    database edit, a restore, a migration. Omitting app_base_url here left the
    three disagreeing — the config endpoint advertised the flow, the login page
    offered "Forgot password?", and the request then issued nothing at all
    because require_app_base_url() rejected it downstream. The user was told to
    check their inbox and no email ever arrived.

    Checking non-empty is not enough either. A restored or directly edited
    value can be non-empty but structurally unusable (`ftp://host`,
    `https://host?next=x`) — require_app_base_url() (services/password_reset.py)
    rejects those at issuance via this same looks_like_public_url(), so a
    value that passes here and fails there leaves this gate and the actual
    issuance path disagreeing about whether the feature works. Concretely:
    register() consults this to decide whether to demand a welcome link
    instead of an admin-chosen password, and with a malformed URL it forced
    the welcome-link path, which then failed downstream and rolled the whole
    account creation back with a 502 — an admin who could have just supplied
    a password was told not to, then told account creation failed anyway.

    smtp_host gets the same treatment for the same reason, via
    looks_like_smtp_host(): a syntactically impossible value ("not a host",
    or one containing a control character) previously passed as "configured"
    here and in build_smtp_config alike, so an admin reset invalidated the
    target's password before the resulting predictable DNS failure was ever
    discovered — the same write-time/read-time disagreement this whole
    effective-state gate exists to prevent for app_base_url.

    smtp_port and smtp_tls_mode get the same treatment for the same reason:
    this function is what forgot_password and reset_password
    (api/users.py, admin-initiated) both consult before deciding whether to
    actually attempt issuance. If this said "enabled" for a config that
    build_smtp_config would then refuse (see parse_smtp_port,
    parse_smtp_tls_mode, parse_smtp_from_addr), forgot_password reaches
    prepare_reset_email only for a real, active account — recreating the
    exact account enumeration by status code that function's own docstring
    describes — and reset_password invalidates the account's password
    before discovering it cannot deliver a link at all, instead of taking
    the generated-password fallback below. For smtp_tls_mode specifically,
    the alternative — treating an unrecognised value as usable — would let
    this gate advertise the feature as available while the actual send
    silently downgrades to an unencrypted connection, which is a
    materially worse failure mode than merely refusing to send at all. For
    smtp_from specifically, the alternative is worse still: a value
    containing CR/LF does not merely degrade delivery, it raises an
    uncaught ValueError partway through issuance — after set_password has
    already invalidated the admin-reset target's password, or after
    register() has already committed the new user row.
    """
    smtp_host = (settings_map.get("smtp_host") or "").strip()
    if not smtp_host or not looks_like_smtp_host(smtp_host):
        return False
    if parse_smtp_port(settings_map.get("smtp_port")) is None:
        return False
    if parse_smtp_tls_mode(settings_map.get("smtp_tls_mode")) is None:
        return False
    if parse_smtp_from_addr(settings_map.get("smtp_from")) is None:
        return False
    base_url = (settings_map.get("app_base_url") or "").strip()
    if not base_url or not looks_like_public_url(base_url):
        return False
    return setting_is_true(settings_map.get("self_service_password_reset"))
