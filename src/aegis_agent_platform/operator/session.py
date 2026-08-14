"""Server-side operator sessions and one-use OIDC PKCE state."""

from __future__ import annotations

import base64
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe

from aegis_agent_platform.identity import Principal

SESSION_LIFETIME = timedelta(minutes=30)
SESSION_ROTATION_AGE = timedelta(minutes=10)
OIDC_STATE_LIFETIME = timedelta(minutes=5)


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class OperatorSession:
    """Server-only session metadata; bearer credentials never reach JavaScript."""

    session_digest: str
    csrf_digest: str
    principal: Principal
    created_at: datetime
    expires_at: datetime
    authenticated_at: datetime
    rotation: int = 0

    def __post_init__(self) -> None:
        if any(
            value.tzinfo is None
            for value in (self.created_at, self.expires_at, self.authenticated_at)
        ):
            raise ValueError("session times must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("session expiry must follow creation")
        if self.rotation < 0:
            raise ValueError("session rotation cannot be negative")


@dataclass(frozen=True, slots=True)
class OperatorSessionHandle:
    """Opaque cookie and CSRF value returned only at creation or rotation."""

    session_id: str
    csrf_token: str
    session: OperatorSession


class InMemoryOperatorSessionStore:
    """Deterministic fake store; production requires a shared encrypted adapter."""

    def __init__(
        self,
        *,
        token_factory: Callable[[], str] = lambda: token_urlsafe(32),
    ) -> None:
        self._token_factory = token_factory
        self._sessions: dict[str, OperatorSession] = {}

    def create(
        self,
        principal: Principal,
        *,
        now: datetime,
        authenticated_at: datetime | None = None,
    ) -> OperatorSessionHandle:
        session_id = self._token_factory()
        csrf_token = self._token_factory()
        if len(session_id) < 32 or len(csrf_token) < 32:
            raise ValueError("session token factory must return at least 32 characters")
        session = OperatorSession(
            _digest(session_id),
            _digest(csrf_token),
            principal,
            now,
            now + SESSION_LIFETIME,
            authenticated_at or now,
        )
        self._sessions[session.session_digest] = session
        return OperatorSessionHandle(session_id, csrf_token, session)

    def resolve(
        self, session_id: str | None, *, now: datetime
    ) -> OperatorSession | None:
        if not session_id:
            return None
        digest = _digest(session_id)
        session = self._sessions.get(digest)
        if session is None:
            return None
        if now >= session.expires_at:
            del self._sessions[digest]
            return None
        return session

    def validate_csrf(self, session: OperatorSession, token: str | None) -> bool:
        return token is not None and hmac.compare_digest(
            session.csrf_digest,
            _digest(token),
        )

    def needs_rotation(self, session: OperatorSession, *, now: datetime) -> bool:
        return now - session.created_at >= SESSION_ROTATION_AGE

    def rotate(
        self,
        session_id: str,
        session: OperatorSession,
        *,
        now: datetime,
    ) -> OperatorSessionHandle:
        self._sessions.pop(_digest(session_id), None)
        handle = self.create(
            session.principal,
            now=now,
            authenticated_at=session.authenticated_at,
        )
        rotated = OperatorSession(
            handle.session.session_digest,
            handle.session.csrf_digest,
            handle.session.principal,
            handle.session.created_at,
            handle.session.expires_at,
            handle.session.authenticated_at,
            session.rotation + 1,
        )
        self._sessions[rotated.session_digest] = rotated
        return OperatorSessionHandle(handle.session_id, handle.csrf_token, rotated)

    def invalidate(self, session_id: str | None) -> None:
        if session_id:
            self._sessions.pop(_digest(session_id), None)


@dataclass(frozen=True, slots=True)
class OidcAuthorizationState:
    """One-use state binding for an Authorization Code + PKCE flow."""

    state_digest: str
    nonce_digest: str
    verifier_digest: str
    code_challenge: str
    return_path: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class OidcAuthorizationHandle:
    """Values needed to build the authorization request and callback cookie."""

    state: str
    nonce: str
    code_verifier: str
    record: OidcAuthorizationState


class OidcAuthorizationStateStore:
    """One-use PKCE/state/nonce boundary; token exchange remains adapter-owned."""

    def __init__(
        self,
        *,
        token_factory: Callable[[], str] = lambda: token_urlsafe(48),
    ) -> None:
        self._token_factory = token_factory
        self._states: dict[str, OidcAuthorizationState] = {}

    def begin(self, *, return_path: str, now: datetime) -> OidcAuthorizationHandle:
        if (
            not return_path.startswith("/")
            or return_path.startswith("//")
            or len(return_path) > 512
        ):
            raise ValueError("OIDC return path must be a bounded local path")
        state = self._token_factory()
        nonce = self._token_factory()
        verifier = self._token_factory()
        if min(map(len, (state, nonce, verifier))) < 43:
            raise ValueError("OIDC token factory must return at least 43 characters")
        challenge = (
            base64.urlsafe_b64encode(sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        record = OidcAuthorizationState(
            _digest(state),
            _digest(nonce),
            _digest(verifier),
            challenge,
            return_path,
            now + OIDC_STATE_LIFETIME,
        )
        self._states[record.state_digest] = record
        return OidcAuthorizationHandle(state, nonce, verifier, record)

    def consume(
        self,
        *,
        state: str,
        nonce: str,
        code_verifier: str,
        now: datetime,
    ) -> OidcAuthorizationState:
        state_digest = _digest(state)
        record = self._states.pop(state_digest, None)
        if record is None or now >= record.expires_at:
            raise ValueError("OIDC authorization state is missing or expired")
        if not hmac.compare_digest(record.nonce_digest, _digest(nonce)):
            raise ValueError("OIDC nonce does not match")
        if not hmac.compare_digest(record.verifier_digest, _digest(code_verifier)):
            raise ValueError("OIDC verifier does not match")
        return record


__all__ = [
    "OIDC_STATE_LIFETIME",
    "SESSION_LIFETIME",
    "SESSION_ROTATION_AGE",
    "InMemoryOperatorSessionStore",
    "OidcAuthorizationHandle",
    "OidcAuthorizationState",
    "OidcAuthorizationStateStore",
    "OperatorSession",
    "OperatorSessionHandle",
]
