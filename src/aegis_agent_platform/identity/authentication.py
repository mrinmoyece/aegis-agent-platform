"""OIDC JWT verification and authoritative principal resolution."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Lock
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aegis_agent_platform.identity.models import (
    Principal,
    PrincipalKind,
    RoleBinding,
    ServiceIdentity,
    TenantId,
    UserId,
)


class AuthenticationErrorCode(StrEnum):
    """Stable classifications returned without exposing token material."""

    MISSING_TOKEN = "missing_token"  # noqa: S105
    MALFORMED_TOKEN = "malformed_token"  # noqa: S105
    EXPIRED_TOKEN = "expired_token"  # noqa: S105
    WRONG_ISSUER = "wrong_issuer"
    WRONG_AUDIENCE = "wrong_audience"
    INVALID_SIGNATURE = "invalid_signature"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    SIGNING_KEY_UNAVAILABLE = "signing_key_unavailable"
    INVALID_CLAIMS = "invalid_claims"
    UNKNOWN_IDENTITY = "unknown_identity"
    TENANT_MISMATCH = "tenant_mismatch"
    IDENTITY_DISABLED = "identity_disabled"


class AuthenticationError(Exception):
    """Classified authentication failure whose representation is secret-safe."""

    def __init__(self, code: AuthenticationErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __repr__(self) -> str:
        return f"AuthenticationError(code={self.code.value!r})"


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """Provider-neutral public verification key."""

    key_id: str
    algorithm: str
    pem: bytes

    def __post_init__(self) -> None:
        if not self.key_id or not self.algorithm or not self.pem:
            raise ValueError("verification key fields are required")


class JwksProvider(Protocol):
    """Resolve public signing keys without leaking a vendor SDK into core code."""

    def get_key(self, key_id: str) -> VerificationKey:
        """Return a trusted verification key or raise AuthenticationError."""
        ...


class StaticJwksProvider:
    """Deterministic JWKS test double and offline verifier source."""

    def __init__(self, keys: tuple[VerificationKey, ...]) -> None:
        self._keys = {key.key_id: key for key in keys}

    def get_key(self, key_id: str) -> VerificationKey:
        try:
            return self._keys[key_id]
        except KeyError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE,
                "signing key was not found",
            ) from error


class RemoteJwksProvider:
    """Small cached adapter for Keycloak-compatible JWKS endpoints."""

    def __init__(
        self,
        jwks_url: str,
        *,
        timeout_seconds: float = 2.0,
        allow_http: bool = False,
        cache_ttl_seconds: float = 300.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not jwks_url.startswith("https://") and not (
            allow_http and jwks_url.startswith("http://")
        ):
            raise ValueError("JWKS URL must use HTTPS outside explicit development")
        if not 1.0 <= cache_ttl_seconds <= 3_600.0:
            raise ValueError("JWKS cache TTL must be between 1 and 3600 seconds")
        self._jwks_url = jwks_url
        self._allow_http = allow_http
        self._timeout_seconds = timeout_seconds
        self._cache_ttl_seconds = cache_ttl_seconds
        self._monotonic = monotonic
        self._lock = Lock()
        self._cached_keys: dict[str, VerificationKey] = {}
        self._document_expires_at = 0.0

    def get_key(self, key_id: str) -> VerificationKey:
        now = self._monotonic()
        with self._lock:
            if now >= self._document_expires_at:
                self._refresh(now)
            key = self._cached_keys.get(key_id)
            if key is not None:
                return key
        raise AuthenticationError(
            AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE,
            "signing key was not found",
        )

    def _refresh(self, now: float) -> None:
        request = Request(  # noqa: S310 - URL scheme is constrained above
            self._jwks_url,
            headers={"Accept": "application/json"},
        )
        try:
            with urlopen(  # noqa: S310 - URL scheme is constrained above
                request,
                timeout=self._timeout_seconds,
            ) as response:
                final_url: str = response.geturl()
                if not final_url.startswith("https://") and not (
                    self._allow_http and final_url.startswith("http://")
                ):
                    raise AuthenticationError(
                        AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE,
                        "JWKS endpoint redirected to a non-HTTPS URL",
                    )
                document = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            raise AuthenticationError(
                AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE,
                "JWKS endpoint could not provide signing keys",
            ) from error
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise AuthenticationError(
                AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE,
                "JWKS document is invalid",
            )
        refreshed_keys: dict[str, VerificationKey] = {}
        for raw_key in document["keys"]:
            key = _parse_rsa_jwk(raw_key)
            if key is not None:
                refreshed_keys[key.key_id] = key
        self._cached_keys = refreshed_keys
        self._document_expires_at = now + self._cache_ttl_seconds


def _parse_rsa_jwk(raw_key: object) -> VerificationKey | None:
    if not isinstance(raw_key, dict):
        return None
    required = ("kid", "alg", "kty", "n", "e")
    if not all(isinstance(raw_key.get(field), str) for field in required):
        return None
    if raw_key["kty"] != "RSA":
        return None
    try:
        modulus = int.from_bytes(jwt.utils.base64url_decode(raw_key["n"]), "big")
        exponent = int.from_bytes(jwt.utils.base64url_decode(raw_key["e"]), "big")
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except (TypeError, ValueError) as error:
        raise AuthenticationError(
            AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE,
            "JWKS key material is invalid",
        ) from error
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return VerificationKey(
        key_id=raw_key["kid"],
        algorithm=raw_key["alg"],
        pem=pem,
    )


@dataclass(frozen=True, slots=True)
class JwtValidationConfig:
    """Trusted JWT validation inputs supplied by deployment configuration."""

    issuer: str
    audience: str
    clock_skew: timedelta = timedelta(seconds=30)
    algorithms: tuple[str, ...] = ("RS256",)

    def __post_init__(self) -> None:
        if not self.issuer or not self.audience:
            raise ValueError("issuer and audience are required")
        if self.clock_skew < timedelta(0) or self.clock_skew > timedelta(minutes=5):
            raise ValueError("clock skew must be between zero and five minutes")
        if not self.algorithms:
            raise ValueError("at least one signing algorithm is required")


@dataclass(frozen=True, slots=True)
class VerifiedClaims:
    """Minimal verified claim set; authorization claims are intentionally absent."""

    issuer: str
    subject: str
    audiences: tuple[str, ...]
    expires_at: datetime
    issued_at: datetime
    asserted_tenant_id: TenantId | None
    authorized_party: str | None


class JwtVerifier:
    """Validate signature and registered OIDC claims against trusted settings."""

    def __init__(
        self,
        config: JwtValidationConfig,
        jwks: JwksProvider,
    ) -> None:
        self._config = config
        self._jwks = jwks

    def verify(self, token: str) -> VerifiedClaims:
        if not token:
            raise AuthenticationError(
                AuthenticationErrorCode.MISSING_TOKEN,
                "bearer token is required",
            )
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.MALFORMED_TOKEN,
                "bearer token is malformed",
            ) from error
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if not isinstance(algorithm, str) or algorithm not in self._config.algorithms:
            raise AuthenticationError(
                AuthenticationErrorCode.UNSUPPORTED_ALGORITHM,
                "token signing algorithm is not allowed",
            )
        if not isinstance(key_id, str) or not key_id:
            raise AuthenticationError(
                AuthenticationErrorCode.MALFORMED_TOKEN,
                "token does not identify a signing key",
            )
        key = self._jwks.get_key(key_id)
        if key.algorithm != algorithm:
            raise AuthenticationError(
                AuthenticationErrorCode.UNSUPPORTED_ALGORITHM,
                "token and signing key algorithms do not match",
            )
        try:
            payload = jwt.decode(
                token,
                key.pem,
                algorithms=list(self._config.algorithms),
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.clock_skew,
                options={"require": ["aud", "exp", "iat", "iss", "sub"]},
            )
        except jwt.ExpiredSignatureError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.EXPIRED_TOKEN,
                "bearer token has expired",
            ) from error
        except jwt.InvalidIssuerError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.WRONG_ISSUER,
                "bearer token issuer is not trusted",
            ) from error
        except jwt.InvalidAudienceError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.WRONG_AUDIENCE,
                "bearer token audience is not accepted",
            ) from error
        except jwt.InvalidSignatureError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.INVALID_SIGNATURE,
                "bearer token signature is invalid",
            ) from error
        except jwt.InvalidTokenError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.INVALID_CLAIMS,
                "bearer token claims are invalid",
            ) from error
        return _verified_claims(payload)


def _verified_claims(payload: Mapping[str, object]) -> VerifiedClaims:
    subject = payload.get("sub")
    issuer = payload.get("iss")
    expires_at = payload.get("exp")
    issued_at = payload.get("iat")
    audience = payload.get("aud")
    if (
        not isinstance(subject, str)
        or not subject
        or not isinstance(issuer, str)
        or not isinstance(expires_at, (int, float))
        or not isinstance(issued_at, (int, float))
    ):
        raise AuthenticationError(
            AuthenticationErrorCode.INVALID_CLAIMS,
            "required token claims have invalid types",
        )
    if isinstance(audience, str):
        audiences = (audience,)
    elif isinstance(audience, list) and all(isinstance(item, str) for item in audience):
        audiences = tuple(audience)
    else:
        raise AuthenticationError(
            AuthenticationErrorCode.INVALID_CLAIMS,
            "audience claim has an invalid type",
        )
    raw_tenant_id = payload.get("tenant_id")
    try:
        asserted_tenant_id = (
            TenantId(raw_tenant_id) if isinstance(raw_tenant_id, str) else None
        )
    except ValueError as error:
        raise AuthenticationError(
            AuthenticationErrorCode.INVALID_CLAIMS,
            "tenant claim has an invalid value",
        ) from error
    authorized_party = payload.get("azp")
    if authorized_party is not None and not isinstance(authorized_party, str):
        raise AuthenticationError(
            AuthenticationErrorCode.INVALID_CLAIMS,
            "authorized party claim has an invalid type",
        )
    return VerifiedClaims(
        issuer=issuer,
        subject=subject,
        audiences=audiences,
        expires_at=datetime.fromtimestamp(expires_at, UTC),
        issued_at=datetime.fromtimestamp(issued_at, UTC),
        asserted_tenant_id=asserted_tenant_id,
        authorized_party=authorized_party,
    )


@dataclass(frozen=True, slots=True)
class IdentityRecord:
    """Authoritative mapping from external subject to internal identity."""

    issuer: str
    subject: str
    tenant_id: TenantId
    kind: PrincipalKind
    role_bindings: tuple[RoleBinding, ...]
    enabled: bool = True
    user_id: UserId | None = None
    service_identity: ServiceIdentity | None = None

    def to_principal(self) -> Principal:
        return Principal(
            subject=self.subject,
            issuer=self.issuer,
            tenant_id=self.tenant_id,
            kind=self.kind,
            role_bindings=self.role_bindings,
            user_id=self.user_id,
            service_identity=self.service_identity,
        )


class IdentityDirectory(Protocol):
    """Resolve verified external subjects through authoritative local records."""

    def resolve(self, claims: VerifiedClaims) -> Principal:
        """Return a principal or raise a classified authentication error."""
        ...


class InMemoryIdentityDirectory:
    """Deterministic identity repository used by tests and local development."""

    def __init__(self, records: tuple[IdentityRecord, ...]) -> None:
        self._records = {(record.issuer, record.subject): record for record in records}

    def resolve(self, claims: VerifiedClaims) -> Principal:
        try:
            record = self._records[(claims.issuer, claims.subject)]
        except KeyError as error:
            raise AuthenticationError(
                AuthenticationErrorCode.UNKNOWN_IDENTITY,
                "verified subject is not registered",
            ) from error
        if not record.enabled:
            raise AuthenticationError(
                AuthenticationErrorCode.IDENTITY_DISABLED,
                "identity is disabled",
            )
        if (
            claims.asserted_tenant_id is not None
            and claims.asserted_tenant_id != record.tenant_id
        ):
            raise AuthenticationError(
                AuthenticationErrorCode.TENANT_MISMATCH,
                "signed tenant claim does not match the identity record",
            )
        return record.to_principal()


class AuthenticationService:
    """Authenticate bearer credentials without accepting caller identity headers."""

    def __init__(
        self,
        verifier: JwtVerifier,
        directory: IdentityDirectory,
    ) -> None:
        self._verifier = verifier
        self._directory = directory

    def authenticate(self, authorization_header: str | None) -> Principal:
        if authorization_header is None:
            raise AuthenticationError(
                AuthenticationErrorCode.MISSING_TOKEN,
                "authorization header is required",
            )
        scheme, separator, token = authorization_header.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token.strip():
            raise AuthenticationError(
                AuthenticationErrorCode.MALFORMED_TOKEN,
                "authorization header must contain a bearer token",
            )
        claims = self._verifier.verify(token.strip())
        return self._directory.resolve(claims)
