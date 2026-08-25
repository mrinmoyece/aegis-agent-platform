"""Validate pinned MCP/A2A compatibility and architectural drift."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from aegis_agent_platform.integrations.a2a.adapter import (
    A2A_PROTOCOL_VERSION,
    A2A_SPEC_TAG,
)
from aegis_agent_platform.integrations.mcp.adapter import (
    MCP_CURRENT_VERSION,
    MCP_SUPPORTED_VERSIONS,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        dependencies = frozenset(tomllib.load(handle)["project"]["dependencies"])
    required_dependencies = {"mcp==2.0.0", "a2a-sdk==1.1.2"}
    if not required_dependencies <= dependencies:
        raise SystemExit("official MCP/A2A SDK pins drifted")
    if MCP_CURRENT_VERSION != "2026-07-28" or MCP_SUPPORTED_VERSIONS[0] != (
        MCP_CURRENT_VERSION
    ):
        raise SystemExit("MCP current-version negotiation drifted")
    if A2A_PROTOCOL_VERSION != "1.0" or A2A_SPEC_TAG != "v1.0.1":
        raise SystemExit("A2A protocol/spec compatibility drifted")

    domain = (ROOT / "src/aegis_agent_platform/domain/protocols.py").read_text(
        encoding="utf-8"
    )
    if any(marker in domain for marker in ("import mcp", "from mcp", "import a2a")):
        raise SystemExit("protocol SDK types crossed into the domain boundary")
    if "ProtocolTransport.SSE" in domain or '"sse"' in domain:
        raise SystemExit("obsolete standalone MCP HTTP+SSE transport is forbidden")

    migration = (ROOT / "migrations/0010_mcp_a2a_interoperability.sql").read_text(
        encoding="utf-8"
    )
    for table in (
        "protocol_peer_registry",
        "protocol_operation_projection",
        "protocol_operation_claims",
        "protocol_stream_cursors",
        "protocol_quota_projection",
        "protocol_audit_projection",
    ):
        if (
            f"CREATE TABLE {table}" not in migration
            or f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" not in migration
        ):
            raise SystemExit(f"protocol migration lost forced RLS for {table}")

    contract = ROOT / "contracts/operator-api.openapi.json"
    with contract.open(encoding="utf-8") as handle:
        openapi = json.load(handle)
    trust_path = "/tenants/{tenantId}/protocol-peers/{peerId}/trust/record"
    if trust_path not in openapi["paths"]:
        raise SystemExit("operator protocol trust contract is missing")

    compatibility = (ROOT / "docs/protocols.md").read_text(encoding="utf-8")
    for marker in (
        "2026-07-28",
        "mcp==2.0.0",
        "v1.0.1",
        "a2a-sdk==1.1.2",
        "standalone HTTP+SSE is rejected",
    ):
        if marker not in compatibility:
            raise SystemExit(f"protocol compatibility documentation missing: {marker}")


if __name__ == "__main__":
    main()
