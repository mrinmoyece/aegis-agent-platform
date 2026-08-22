"""Production GitHub App evidence adapter with repository confinement."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from aegis_agent_platform.domain import (
    ChangeReference,
    DeploymentReference,
    EvidenceKind,
    EvidenceReference,
    EvidenceSourceKind,
    PartialResult,
    ServiceIdentity,
    TrustStatus,
    require_aware_datetime,
)
from aegis_agent_platform.evidence import (
    CancellationSignal,
    ConnectorCapability,
    ConnectorError,
    ConnectorErrorClass,
    ConnectorPage,
    EvidenceQuery,
    HttpRequest,
    HttpTransport,
    RawEvidence,
)
from aegis_agent_platform.integrations._http import (
    classify_status,
    json_mapping,
    json_sequence,
)
from aegis_agent_platform.integrations._pagination import decode_cursor, encode_cursor
from aegis_agent_platform.integrations.config import GitHubConnectorConfig
from aegis_agent_platform.secrets_boundary import SecretProvider
from aegis_agent_platform.tenancy import TenantContext


class ChangeKind(StrEnum):
    """Source and delivery changes relevant to incident correlation."""

    COMMIT = "commit"
    PULL_REQUEST = "pull_request"
    DEPLOYMENT = "deployment"


@dataclass(frozen=True, slots=True)
class ChangeEvidence:
    """Normalized GitHub evidence with a stable source reference."""

    reference: str
    repository: str
    revision: str
    kind: ChangeKind
    observed_at: datetime
    summary: str

    def __post_init__(self) -> None:
        """Require a timestamp safe for cross-source incident correlation."""
        require_aware_datetime(self.observed_at, field_name="observed_at")


class GitHubEvidenceReader(Protocol):
    """Tenant-scoped read port; implementations arrive in a later layer."""

    async def changes_between(
        self,
        *,
        tenant: TenantContext,
        repository: str,
        start: datetime,
        end: datetime,
    ) -> Sequence[ChangeEvidence]:
        """Read normalized delivery changes within an incident window."""
        ...


_SUPPORTED = (
    EvidenceKind.COMMIT,
    EvidenceKind.PULL_REQUEST,
    EvidenceKind.REVIEW,
    EvidenceKind.CHECK,
    EvidenceKind.WORKFLOW,
    EvidenceKind.DEPLOYMENT,
    EvidenceKind.RELEASE,
    EvidenceKind.TAG,
    EvidenceKind.CHANGE,
)


class GitHubAdapter:
    """GitHub REST adapter using short-lived installation access tokens."""

    source = EvidenceSourceKind.GITHUB

    def __init__(
        self,
        context: TenantContext,
        config: GitHubConnectorConfig,
        secrets: SecretProvider,
        transport: HttpTransport,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if context.tenant_id != config.tenant_id:
            raise PermissionError("cross_tenant_connector_config")
        if not config.enabled:
            raise ValueError("GitHub connector is disabled")
        self._context = context
        self._config = config
        self._secrets = secrets
        self._transport = transport
        self._clock = clock

    async def capability(self) -> ConnectorCapability:
        return ConnectorCapability(
            self.source,
            _SUPPORTED,
            "rest-2022-11-28",
            True,
            "github_app_installation",
        )

    async def query(
        self,
        query: EvidenceQuery,
        *,
        cancellation: CancellationSignal | None = None,
    ) -> ConnectorPage:
        repository = query.selectors.get("repository")
        if query.tenant_id != str(self._context.tenant_id):
            raise PermissionError("cross_tenant_query")
        if repository not in self._config.repositories:
            raise PermissionError("repository_not_allowed")
        if query.window.end - query.window.start > _window(
            self._config.limits.max_window_seconds
        ):
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "query_window_too_large",
                retryable=False,
            )
        if any(kind not in _SUPPORTED for kind in query.kinds):
            raise ConnectorError(
                ConnectorErrorClass.CAPABILITY,
                "unsupported_evidence_kind",
                retryable=False,
            )
        if len(query.kinds) != 1:
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "github_single_kind_required",
                retryable=False,
            )
        if cancellation is not None and cancellation.cancelled:
            raise ConnectorError(
                ConnectorErrorClass.CANCELLED,
                "query_cancelled",
                retryable=False,
            )
        token = await self._installation_token()
        if query.kinds[0] is EvidenceKind.CHANGE:
            return await self._query_compare(
                query,
                repository,
                token,
                cancellation,
            )
        records: list[RawEvidence] = []
        reasons: list[str] = []
        cursor_state = decode_cursor(
            query.cursor,
            allowed_keys=tuple(kind.value for kind in query.kinds),
        )
        next_cursors: dict[str, str] = {}
        active_kinds = (
            query.kinds
            if cursor_state is None
            else tuple(kind for kind in query.kinds if kind.value in cursor_state)
        )
        for kind in active_kinds:
            response = await self._transport.send(
                self._request(
                    query,
                    repository,
                    kind,
                    token,
                    cursor_state.get(kind.value) if cursor_state else None,
                )
            )
            if response.status == 304:
                reasons.append("not_modified_without_cached_representation")
                continue
            items = _github_items(response, kind)
            if kind is EvidenceKind.TAG:
                resolved_tags: list[Mapping[str, object]] = []
                for item in items[: min(query.limit, self._config.limits.max_records)]:
                    resolved = await self._resolve_tag(repository, item, token)
                    if resolved is None:
                        reasons.append("lightweight_tag_timestamp_unavailable")
                    else:
                        resolved_tags.append(resolved)
                items = tuple(resolved_tags)
            for item in items:
                if len(records) >= min(query.limit, self._config.limits.max_records):
                    reasons.append("record_cap")
                    break
                raw = _normalize(item, kind, repository)
                if query.window.start <= raw.observed_at <= query.window.end:
                    records.append(raw)
            if 'rel="next"' in response.headers.get("link", ""):
                current_page = (
                    cursor_state[kind.value] if cursor_state is not None else "1"
                )
                if not current_page.isdigit() or int(current_page) < 1:
                    raise ConnectorError(
                        ConnectorErrorClass.INVALID_QUERY,
                        "github_cursor_invalid",
                        retryable=False,
                    )
                next_cursors[kind.value] = str(int(current_page) + 1)
                reasons.append("upstream_pagination")
        return ConnectorPage(
            records,
            encode_cursor(next_cursors),
            PartialResult(
                bool(reasons),
                "record_cap" in reasons,
                tuple(sorted(set(reasons))),
            ),
        )

    async def _query_compare(
        self,
        query: EvidenceQuery,
        repository: str,
        token: str,
        cancellation: CancellationSignal | None,
    ) -> ConnectorPage:
        if query.cursor is not None:
            raise ConnectorError(
                ConnectorErrorClass.INVALID_QUERY,
                "github_compare_cursor_unsupported",
                retryable=False,
            )
        if cancellation is not None and cancellation.cancelled:
            raise ConnectorError(
                ConnectorErrorClass.CANCELLED,
                "query_cancelled",
                retryable=False,
            )
        head_ref = _required_ref(query, "head")
        root = self._config.api_url.rstrip("/") + f"/repos/{repository}"
        head = json_mapping(
            await self._transport.send(
                HttpRequest(
                    "GET",
                    root + "/commits/" + quote(head_ref, safe=""),
                    {
                        "authorization": _authorization(token),
                        "accept": "application/vnd.github+json",
                        "x-github-api-version": "2022-11-28",
                    },
                    self._config.limits.timeout_seconds,
                    self._config.limits.max_response_bytes,
                )
            )
        )
        head_sha = head.get("sha")
        commit = head.get("commit")
        commit_mapping = commit if isinstance(commit, Mapping) else {}
        head_time = _github_time(head, commit_mapping)
        if not isinstance(head_sha, str) or not head_sha:
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "github_compare_head_missing",
                retryable=False,
            )
        response = await self._transport.send(
            self._request(query, repository, EvidenceKind.CHANGE, token, None)
        )
        item, omitted = _github_compare_item(response, query, head_sha, head_time)
        raw = _normalize(item, EvidenceKind.CHANGE, repository)
        records = (
            (raw,) if query.window.start <= raw.observed_at <= query.window.end else ()
        )
        reasons: tuple[str, ...] = ()
        if omitted:
            reasons = ("compare_commit_details_omitted",)
        return ConnectorPage(
            records,
            None,
            PartialResult(
                partial=bool(reasons),
                truncated=bool(reasons),
                reasons=reasons,
                omitted_records=omitted,
            ),
        )

    async def _resolve_tag(
        self,
        repository: str,
        item: Mapping[str, object],
        token: str,
    ) -> Mapping[str, object] | None:
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "github_tag_name_missing",
                retryable=False,
            )
        root = self._config.api_url.rstrip("/") + f"/repos/{repository}"
        url = root + "/git/ref/tags/" + quote(name, safe="")
        payload = json_mapping(
            await self._transport.send(
                HttpRequest(
                    "GET",
                    url,
                    {
                        "authorization": "******",
                        "accept": "application/vnd.github+json",
                        "x-github-api-version": "2022-11-28",
                    },
                    self._config.limits.timeout_seconds,
                    self._config.limits.max_response_bytes,
                )
            )
        )
        target = payload.get("object")
        if not isinstance(target, Mapping):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "github_tag_target_missing",
                retryable=False,
            )
        if target.get("type") != "tag":
            return None
        tag_url = target.get("url")
        if not isinstance(tag_url, str) or not tag_url.startswith(root + "/git/tags/"):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "github_tag_object_url_invalid",
                retryable=False,
            )
        tag = json_mapping(
            await self._transport.send(
                HttpRequest(
                    "GET",
                    tag_url,
                    {
                        "authorization": "******",
                        "accept": "application/vnd.github+json",
                        "x-github-api-version": "2022-11-28",
                    },
                    self._config.limits.timeout_seconds,
                    self._config.limits.max_response_bytes,
                )
            )
        )
        tagger = tag.get("tagger")
        object_target = tag.get("object")
        if not isinstance(tagger, Mapping) or not isinstance(object_target, Mapping):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "github_annotated_tag_invalid",
                retryable=False,
            )
        return {
            "id": f"tag:{name}",
            "name": name,
            "updated_at": tagger.get("date"),
            "sha": object_target.get("sha", ""),
            "html_url": f"https://github.com/{repository}/tree/{quote(name, safe='')}",
        }

    async def _installation_token(self) -> str:
        jwt = self._app_jwt()
        response = await self._transport.send(
            HttpRequest(
                "POST",
                (
                    self._config.api_url.rstrip("/")
                    + f"/app/installations/{self._config.installation_id}/access_tokens"
                ),
                {
                    "authorization": f"Bearer {jwt}",
                    "accept": "application/vnd.github+json",
                    "x-github-api-version": "2022-11-28",
                    "content-type": "application/json",
                },
                self._config.limits.timeout_seconds,
                128_000,
                b"{}",
            )
        )
        payload = json_mapping(response)
        token = payload.get("token")
        if not isinstance(token, str) or not token:
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "github_installation_token_missing",
                retryable=False,
            )
        return token

    def _app_jwt(self) -> str:
        now = int(self._clock().timestamp())
        header = _b64(
            json.dumps(
                {"alg": "RS256", "typ": "JWT"},
                separators=(",", ":"),
            ).encode()
        )
        payload = _b64(
            json.dumps(
                {"iat": now - 30, "exp": now + 540, "iss": self._config.app_id},
                separators=(",", ":"),
            ).encode()
        )
        signing_input = f"{header}.{payload}".encode()
        key_bytes = self._secrets.resolve(
            self._context, self._config.private_key
        ).reveal()
        try:
            private_key = serialization.load_pem_private_key(key_bytes, password=None)
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("GitHub App key must be RSA")
            signature = private_key.sign(signing_input, PKCS1v15(), hashes.SHA256())
        except (TypeError, ValueError) as error:
            raise ConnectorError(
                ConnectorErrorClass.AUTHENTICATION,
                "github_private_key_invalid",
                retryable=False,
            ) from error
        return f"{header}.{payload}.{_b64(signature)}"

    def _request(
        self,
        query: EvidenceQuery,
        repository: str,
        kind: EvidenceKind,
        token: str,
        page: str | None,
    ) -> HttpRequest:
        owner, name = repository.split("/", maxsplit=1)
        root = f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
        paths = {
            EvidenceKind.COMMIT: "/commits",
            EvidenceKind.PULL_REQUEST: "/pulls",
            EvidenceKind.WORKFLOW: "/actions/runs",
            EvidenceKind.DEPLOYMENT: "/deployments",
            EvidenceKind.RELEASE: "/releases",
            EvidenceKind.TAG: "/tags",
        }
        if kind is EvidenceKind.REVIEW:
            pull_number = query.selectors.get("pull_request", "")
            if not pull_number.isdigit() or int(pull_number) < 1:
                raise ConnectorError(
                    ConnectorErrorClass.INVALID_QUERY,
                    "github_pull_request_number_required",
                    retryable=False,
                )
            path = f"/pulls/{pull_number}/reviews"
        elif kind is EvidenceKind.CHECK:
            ref = query.selectors.get("ref")
            if (
                ref is None
                or not 1 <= len(ref) <= 256
                or any(character.isspace() for character in ref)
            ):
                raise ConnectorError(
                    ConnectorErrorClass.INVALID_QUERY,
                    "github_check_ref_required",
                    retryable=False,
                )
            path = f"/commits/{quote(ref, safe='')}/check-runs"
        elif kind is EvidenceKind.CHANGE:
            base_ref = _required_ref(query, "base")
            head_ref = _required_ref(query, "head")
            path = f"/compare/{quote(base_ref, safe='')}...{quote(head_ref, safe='')}"
        else:
            path = paths[kind]
        parameters = {
            "per_page": str(min(query.limit, 100)),
            "page": page or "1",
        }
        if kind is EvidenceKind.COMMIT:
            parameters["since"] = query.window.start.astimezone(UTC).isoformat()
            parameters["until"] = query.window.end.astimezone(UTC).isoformat()
        if kind is EvidenceKind.PULL_REQUEST:
            parameters.update({"state": "all", "sort": "updated", "direction": "desc"})
        url = self._config.api_url.rstrip("/") + root + path
        headers = {
            "authorization": f"Bearer {token}",
            "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
        }
        return HttpRequest(
            "GET",
            url + "?" + urlencode(parameters),
            headers,
            self._config.limits.timeout_seconds,
            self._config.limits.max_response_bytes,
        )


def _github_items(
    response: object,
    kind: EvidenceKind,
) -> tuple[Mapping[str, object], ...]:
    from aegis_agent_platform.evidence import HttpResponse

    if not isinstance(response, HttpResponse):
        raise TypeError("response must be HttpResponse")
    classify_status(response)
    if kind in {EvidenceKind.CHECK, EvidenceKind.WORKFLOW}:
        payload = json_mapping(response)
        key = "check_runs" if kind is EvidenceKind.CHECK else "workflow_runs"
        value = payload.get(key)
        if not isinstance(value, tuple | list) or not all(
            isinstance(item, Mapping) for item in value
        ):
            raise ConnectorError(
                ConnectorErrorClass.MALFORMED_RESPONSE,
                "github_collection_invalid",
                retryable=False,
            )
        return tuple(value)
    return tuple(json_sequence(response))


def _github_compare_item(
    response: object,
    query: EvidenceQuery,
    head_sha: str,
    head_time: datetime,
) -> tuple[Mapping[str, object], int]:
    from aegis_agent_platform.evidence import HttpResponse

    if not isinstance(response, HttpResponse):
        raise TypeError("response must be HttpResponse")
    payload = json_mapping(response)
    base = payload.get("base_commit")
    merge_base = payload.get("merge_base_commit")
    commits = payload.get("commits")
    files = payload.get("files", [])
    html_url = payload.get("html_url")
    total_commits = payload.get("total_commits")
    if (
        not isinstance(base, Mapping)
        or not isinstance(merge_base, Mapping)
        or not isinstance(commits, list)
        or not all(isinstance(item, Mapping) for item in commits)
        or not isinstance(files, list)
        or not all(isinstance(item, Mapping) for item in files)
        or not isinstance(html_url, str)
        or not html_url.startswith("https://")
        or not isinstance(total_commits, int)
        or isinstance(total_commits, bool)
        or total_commits < 0
    ):
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "github_compare_response_invalid",
            retryable=False,
        )
    base_ref = _required_ref(query, "base")
    head_ref = _required_ref(query, "head")
    identifier = f"compare:{base_ref}...{head_ref}"
    return (
        {
            "id": identifier,
            "name": identifier,
            "sha": head_sha,
            "updated_at": head_time.isoformat(),
            "html_url": html_url,
            "status": payload.get("status"),
            "ahead_by": payload.get("ahead_by"),
            "behind_by": payload.get("behind_by"),
            "total_commits": total_commits,
            "changed_files": len(files),
            "merge_base_sha": merge_base.get("sha"),
        },
        max(0, total_commits - len(commits)),
    )


def _required_ref(query: EvidenceQuery, key: str) -> str:
    value = query.selectors.get(key)
    if (
        value is None
        or not 1 <= len(value) <= 256
        or any(character.isspace() for character in value)
    ):
        raise ConnectorError(
            ConnectorErrorClass.INVALID_QUERY,
            f"github_{key}_ref_required",
            retryable=False,
        )
    return value


def _normalize(
    item: Mapping[str, object],
    kind: EvidenceKind,
    repository: str,
) -> RawEvidence:
    sha = str(item.get("sha", item.get("head_sha", "")))
    identifier = str(item.get("id", item.get("node_id", sha)))
    if not identifier:
        raise ConnectorError(
            ConnectorErrorClass.MALFORMED_RESPONSE,
            "github_record_id_missing",
            retryable=False,
        )
    commit = item.get("commit")
    commit_mapping = commit if isinstance(commit, Mapping) else {}
    observed = _github_time(item, commit_mapping)
    summary = str(
        item.get(
            "name",
            item.get(
                "title",
                commit_mapping.get("message", item.get("ref", kind.value)),
            ),
        )
    ).splitlines()[0][:4096]
    references: list[EvidenceReference] = []
    if sha:
        references.append(ChangeReference(sha, repository))
    if kind is EvidenceKind.DEPLOYMENT:
        revision = str(item.get("ref", sha))
        if revision:
            references.append(DeploymentReference(revision))
    html_url = item.get("html_url")
    provenance = (
        str(html_url)
        if isinstance(html_url, str) and html_url.startswith("https://")
        else f"https://github.com/{repository}"
    )
    safe = {
        key: value
        for key, value in item.items()
        if key
        in {
            "id",
            "node_id",
            "sha",
            "head_sha",
            "ref",
            "state",
            "status",
            "conclusion",
            "created_at",
            "updated_at",
            "started_at",
            "completed_at",
            "published_at",
            "run_number",
            "tag_name",
            "ahead_by",
            "behind_by",
            "total_commits",
            "changed_files",
            "merge_base_sha",
        }
        and (isinstance(value, (str, int, float, bool)) or value is None)
    }
    return RawEvidence(
        identifier,
        kind,
        observed,
        summary,
        safe,
        provenance,
        service=ServiceIdentity(repository.replace("/", "-")),
        references=tuple(references),
        trust=TrustStatus.VERIFIED,
    )


def _github_time(
    item: Mapping[str, object],
    commit: Mapping[str, object],
) -> datetime:
    author = commit.get("author")
    author_mapping = author if isinstance(author, Mapping) else {}
    candidates = (
        item.get("completed_at"),
        item.get("started_at"),
        item.get("updated_at"),
        item.get("created_at"),
        item.get("published_at"),
        item.get("submitted_at"),
        item.get("run_started_at"),
        author_mapping.get("date"),
    )
    for value in candidates:
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed.astimezone(UTC)
            except ValueError:
                continue
    raise ConnectorError(
        ConnectorErrorClass.MALFORMED_RESPONSE,
        "github_timestamp_missing",
        retryable=False,
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _authorization(token: str) -> str:
    return "Bearer " + token


def _window(seconds: int) -> timedelta:
    return timedelta(seconds=seconds)


__all__ = ["ChangeEvidence", "ChangeKind", "GitHubAdapter", "GitHubEvidenceReader"]
