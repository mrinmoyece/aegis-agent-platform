"""Authentication, identity, and authorization security tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.error import URLError

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import aegis_agent_platform.identity.authentication as authentication_module
from aegis_agent_platform.identity import (
    AuthenticationError,
    AuthenticationErrorCode,
    AuthorizationService,
    IdentityRecord,
    InMemoryIdentityDirectory,
    JwtValidationConfig,
    JwtVerifier,
    Permission,
    Principal,
    PrincipalKind,
    RemoteJwksProvider,
    Role,
    ServiceIdentity,
    StaticJwksProvider,
    TenantId,
    UserId,
    VerificationKey,
)
from security_helpers import (
    AUDIENCE,
    ISSUER,
    KEY_ID,
    TENANT_ID,
    authentication_service,
    binding,
    identity_record,
    principal,
    signing_fixture,
    token,
)


@pytest.mark.parametrize(
    ("authorization", "code"),
    [
        (None, AuthenticationErrorCode.MISSING_TOKEN),
        ("Basic abc", AuthenticationErrorCode.MALFORMED_TOKEN),
        ("Bearer ", AuthenticationErrorCode.MALFORMED_TOKEN),
    ],
)
def test_bearer_boundary_rejects_missing_or_malformed_headers(
    authorization: str | None,
    code: AuthenticationErrorCode,
) -> None:
    service = authentication_service(signing_fixture())

    with pytest.raises(AuthenticationError) as captured:
        service.authenticate(authorization)

    assert captured.value.code is code
    assert "abc" not in repr(captured.value)


@pytest.mark.parametrize(
    ("token_kwargs", "code"),
    [
        (
            {"expires_at": datetime.now(UTC) - timedelta(minutes=2)},
            AuthenticationErrorCode.EXPIRED_TOKEN,
        ),
        ({"issuer": "https://evil.example"}, AuthenticationErrorCode.WRONG_ISSUER),
        ({"audience": "other-api"}, AuthenticationErrorCode.WRONG_AUDIENCE),
    ],
)
def test_registered_claim_failures_are_classified(
    token_kwargs: dict[str, object],
    code: AuthenticationErrorCode,
) -> None:
    signing = signing_fixture()
    service = authentication_service(signing)

    with pytest.raises(AuthenticationError) as captured:
        service.authenticate(f"Bearer {token(signing, **token_kwargs)}")  # type: ignore[arg-type]

    assert captured.value.code is code


def test_invalid_signature_is_rejected() -> None:
    signing = signing_fixture()
    attacker_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    encoded = token(signing, private_key=attacker_key)

    with pytest.raises(AuthenticationError) as captured:
        authentication_service(signing).authenticate(f"Bearer {encoded}")

    assert captured.value.code is AuthenticationErrorCode.INVALID_SIGNATURE


def test_malformed_token_and_key_algorithm_mismatch_are_rejected() -> None:
    signing = signing_fixture()
    with pytest.raises(AuthenticationError) as malformed:
        authentication_service(signing).authenticate("Bearer not-a-jwt")
    verifier = JwtVerifier(
        JwtValidationConfig(ISSUER, AUDIENCE),
        StaticJwksProvider((VerificationKey(KEY_ID, "HS256", signing.public_pem),)),
    )

    with pytest.raises(AuthenticationError) as mismatch:
        verifier.verify(token(signing))

    assert malformed.value.code is AuthenticationErrorCode.MALFORMED_TOKEN
    assert mismatch.value.code is AuthenticationErrorCode.UNSUPPORTED_ALGORITHM


def test_clock_skew_is_bounded_and_applied() -> None:
    signing = signing_fixture()
    encoded = token(
        signing,
        expires_at=datetime.now(UTC) - timedelta(seconds=10),
    )

    resolved = authentication_service(signing).authenticate(f"Bearer {encoded}")

    assert resolved.user_id == UserId("user-alice")
    with pytest.raises(ValueError, match="five minutes"):
        JwtValidationConfig(
            issuer=ISSUER,
            audience=AUDIENCE,
            clock_skew=timedelta(minutes=6),
        )


def test_unsupported_algorithm_and_unknown_key_are_rejected() -> None:
    signing = signing_fixture()
    service = authentication_service(signing)
    now = datetime.now(UTC)
    hs_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "oidc-alice",
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=1),
        },
        "test-only-signing-material-over-32-bytes",
        algorithm="HS256",
        headers={"kid": KEY_ID},
    )

    with pytest.raises(AuthenticationError) as unsupported:
        service.authenticate(f"Bearer {hs_token}")
    with pytest.raises(AuthenticationError) as unknown:
        service.authenticate(f"Bearer {token(signing, key_id='missing')}")

    assert unsupported.value.code is AuthenticationErrorCode.UNSUPPORTED_ALGORITHM
    assert unknown.value.code is AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE


def test_authoritative_directory_ignores_token_roles_and_rejects_tenant_confusion() -> (
    None
):
    signing = signing_fixture()
    service = authentication_service(signing)
    encoded = token(
        signing,
        extra_claims={"realm_access": {"roles": ["platform_admin"]}},
    )

    resolved = service.authenticate(f"Bearer {encoded}")

    assert {item.role for item in resolved.role_bindings} == {Role.VIEWER}
    confused = token(signing, tenant_id="tenant-evil")
    with pytest.raises(AuthenticationError) as captured:
        service.authenticate(f"Bearer {confused}")
    assert captured.value.code is AuthenticationErrorCode.TENANT_MISMATCH


@pytest.mark.parametrize(
    ("extra_claims", "code"),
    [
        ({"azp": 7}, AuthenticationErrorCode.INVALID_CLAIMS),
        ({"tenant_id": ""}, AuthenticationErrorCode.INVALID_CLAIMS),
        ({"tenant_id": ["tenant-alpha"]}, AuthenticationErrorCode.INVALID_CLAIMS),
        ({"tenant_id": None}, AuthenticationErrorCode.INVALID_CLAIMS),
    ],
)
def test_invalid_optional_claim_types_are_rejected(
    extra_claims: dict[str, object],
    code: AuthenticationErrorCode,
) -> None:
    signing = signing_fixture()

    with pytest.raises(AuthenticationError) as captured:
        authentication_service(signing).authenticate(
            f"Bearer {token(signing, extra_claims=extra_claims)}"
        )

    assert captured.value.code is code


@pytest.mark.parametrize(
    ("records", "subject", "code"),
    [
        ((), "missing", AuthenticationErrorCode.UNKNOWN_IDENTITY),
        (
            (identity_record(enabled=False),),
            "oidc-alice",
            AuthenticationErrorCode.IDENTITY_DISABLED,
        ),
    ],
)
def test_unknown_and_disabled_identities_are_denied(
    records: tuple[IdentityRecord, ...],
    subject: str,
    code: AuthenticationErrorCode,
) -> None:
    signing = signing_fixture()
    service = authentication_service(signing, records=records)

    with pytest.raises(AuthenticationError) as captured:
        service.authenticate(f"Bearer {token(signing, subject=subject)}")

    assert captured.value.code is code


def test_authorization_denies_cross_tenant_escalation_and_unknown_permissions() -> None:
    service = AuthorizationService()
    viewer = principal()
    now = datetime.now(UTC)

    allowed = service.decide(
        principal=viewer,
        tenant_id=TENANT_ID,
        permission=Permission.TENANT_READ,
        at=now,
    )
    escalated = service.decide(
        principal=viewer,
        tenant_id=TENANT_ID,
        permission=Permission.POLICY_MANAGE,
        at=now,
    )
    confused = service.decide(
        principal=viewer,
        tenant_id=TenantId("tenant-beta"),
        permission=Permission.TENANT_READ,
        at=now,
    )
    unknown = service.decide(
        principal=viewer,
        tenant_id=TENANT_ID,
        permission="future:permission",
        at=now,
    )

    assert allowed.allowed
    assert escalated.reason == "permission_not_granted"
    assert confused.reason == "cross_tenant_access_denied"
    assert unknown.reason == "unknown_permission"


def test_expired_and_revoked_role_bindings_are_stale() -> None:
    now = datetime.now(UTC)
    stale = principal(
        (
            binding(
                Role.TENANT_ADMIN,
                assigned_at=now - timedelta(hours=2),
                expires_at=now - timedelta(hours=1),
            ),
            binding(
                Role.TENANT_ADMIN,
                assigned_at=now - timedelta(hours=2),
                revoked_at=now - timedelta(minutes=1),
            ),
        )
    )

    decision = AuthorizationService().decide(
        principal=stale,
        tenant_id=TENANT_ID,
        permission=Permission.POLICY_MANAGE,
        at=now,
    )

    assert not decision.allowed
    assert decision.active_roles == ()


def test_service_identity_uses_the_same_tenant_authorization_boundary() -> None:
    service_principal = Principal(
        subject="workload-client",
        issuer=ISSUER,
        tenant_id=TENANT_ID,
        kind=PrincipalKind.SERVICE,
        role_bindings=(binding(Role.OPERATOR),),
        service_identity=ServiceIdentity("svc-operator"),
    )

    decision = AuthorizationService().decide(
        principal=service_principal,
        tenant_id=TENANT_ID,
        permission=Permission.OPERATION_PROPOSE,
        at=datetime.now(UTC),
    )

    assert decision.allowed
    assert service_principal.actor_id == "svc-operator"


def test_invalid_principal_and_key_contracts_fail_closed() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        Principal(
            subject="subject",
            issuer=ISSUER,
            tenant_id=TENANT_ID,
            kind=PrincipalKind.USER,
            role_bindings=(),
        )
    with pytest.raises(ValueError, match="verification key"):
        VerificationKey("", "RS256", b"key")
    with pytest.raises(AuthenticationError):
        InMemoryIdentityDirectory(()).resolve(
            JwtVerifier(
                JwtValidationConfig(ISSUER, AUDIENCE),
                StaticJwksProvider(()),
            ).verify("invalid")
        )


class FakeResponse:
    """Minimal urllib response used to keep JWKS tests offline."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback

    def read(self) -> bytes:
        return self._payload


def jwks_document(
    signing_key: rsa.RSAPrivateKey,
    *,
    key_id: str = KEY_ID,
) -> bytes:
    numbers = signing_key.public_key().public_numbers()

    def encoded(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return jwt.utils.base64url_encode(raw).decode()

    return json.dumps(
        {
            "keys": [
                {
                    "kid": key_id,
                    "alg": "RS256",
                    "kty": "RSA",
                    "n": encoded(numbers.n),
                    "e": encoded(numbers.e),
                }
            ]
        }
    ).encode()


def test_remote_jwks_provider_parses_and_caches_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signing = signing_fixture()
    calls: list[float] = []

    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        del request
        calls.append(timeout)
        return FakeResponse(jwks_document(signing.private_key))

    monkeypatch.setattr(authentication_module, "urlopen", fake_urlopen)
    provider = RemoteJwksProvider("https://identity.example/certs")

    first = provider.get_key(KEY_ID)
    second = provider.get_key(KEY_ID)

    assert first == second
    assert first.pem == signing.public_pem
    assert calls == [2.0]


def test_remote_jwks_provider_negative_lookup_uses_document_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signing = signing_fixture()
    calls: list[float] = []

    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        del request
        calls.append(timeout)
        return FakeResponse(jwks_document(signing.private_key))

    monkeypatch.setattr(authentication_module, "urlopen", fake_urlopen)
    provider = RemoteJwksProvider("https://identity.example/certs")

    for key_id in ("attacker-key-1", "attacker-key-2"):
        with pytest.raises(AuthenticationError) as captured:
            provider.get_key(key_id)
        assert captured.value.code is AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE

    assert calls == [2.0]


def test_remote_jwks_provider_refreshes_after_bounded_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_signing = signing_fixture()
    rotated_signing = signing_fixture()
    responses = iter(
        (
            jwks_document(first_signing.private_key),
            jwks_document(rotated_signing.private_key),
        )
    )
    now = [0.0]

    def fake_urlopen(request: object, timeout: float) -> FakeResponse:
        del request, timeout
        return FakeResponse(next(responses))

    monkeypatch.setattr(authentication_module, "urlopen", fake_urlopen)
    provider = RemoteJwksProvider(
        "https://identity.example/certs",
        cache_ttl_seconds=30,
        monotonic=lambda: now[0],
    )

    original = provider.get_key(KEY_ID)
    now[0] = 31.0
    rotated = provider.get_key(KEY_ID)

    assert original.pem == first_signing.public_pem
    assert rotated.pem == rotated_signing.public_pem


def test_remote_jwks_refresh_atomically_removes_retired_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retired_signing = signing_fixture()
    rotated_signing = signing_fixture()
    responses = iter(
        (
            jwks_document(retired_signing.private_key),
            jwks_document(rotated_signing.private_key, key_id="rotated-key"),
        )
    )
    now = [0.0]
    monkeypatch.setattr(
        authentication_module,
        "urlopen",
        lambda request, timeout: FakeResponse(next(responses)),
    )
    provider = RemoteJwksProvider(
        "https://identity.example/certs",
        cache_ttl_seconds=30,
        monotonic=lambda: now[0],
    )

    assert provider.get_key(KEY_ID).pem == retired_signing.public_pem
    now[0] = 31.0
    with pytest.raises(AuthenticationError) as captured:
        provider.get_key(KEY_ID)

    assert captured.value.code is AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE
    assert provider.get_key("rotated-key").pem == rotated_signing.public_pem


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"keys":[]}',
        b'{"keys":[{"kty":"EC"}]}',
        b'{"keys":[{"kid":"bad","alg":"RS256","kty":"RSA","n":"***","e":"AQAB"}]}',
    ],
)
def test_remote_jwks_invalid_documents_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    monkeypatch.setattr(
        authentication_module,
        "urlopen",
        lambda request, timeout: FakeResponse(payload),
    )
    provider = RemoteJwksProvider("https://identity.example/certs")

    with pytest.raises(AuthenticationError) as captured:
        provider.get_key(KEY_ID)

    assert captured.value.code is AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE


def test_remote_jwks_transport_and_scheme_failures_are_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(request: object, timeout: float) -> FakeResponse:
        del request, timeout
        raise URLError("offline")

    monkeypatch.setattr(authentication_module, "urlopen", unavailable)
    with pytest.raises(ValueError, match="HTTPS"):
        RemoteJwksProvider("http://identity.example/certs")
    with pytest.raises(ValueError, match="cache TTL"):
        RemoteJwksProvider(
            "https://identity.example/certs",
            cache_ttl_seconds=0,
        )
    provider = RemoteJwksProvider(
        "http://keycloak:8080/certs",
        allow_http=True,
    )

    with pytest.raises(AuthenticationError) as captured:
        provider.get_key(KEY_ID)

    assert captured.value.code is AuthenticationErrorCode.SIGNING_KEY_UNAVAILABLE


def test_duplicate_identity_records_fail_closed() -> None:
    record = identity_record()

    with pytest.raises(ValueError, match="duplicate authoritative"):
        InMemoryIdentityDirectory((record, record))
