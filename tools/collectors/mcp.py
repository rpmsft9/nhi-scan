"""AI-agent tool manifests (MCP servers / connectors) -> nhi-scan records.

An agent's **reach** is the set of tools it can invoke across its connected MCP servers and
connectors. This collector reads that manifest and emits one nhi-scan record per agent with
``type: ai_agent`` and a populated ``tools`` list — so ``nhi-scan diff`` can track reach growth
(a new connector) even when privilege, credential age, and owner are unchanged.

Gather: export your agents and the servers/tools they're wired to into the shape below, then:

    python -m tools.collectors.mcp agents.json > agents-nhi.json

Expected input (an object with ``agents``, or a bare list):

    {"agents": [
      {"id": "collections-agent", "name": "collections-ai-agent",
       "owner": "cx@bank.example", "environment": "prod", "privilege": "privileged",
       "autonomous": true, "scopes": ["accounts:read"],
       "servers": [
         {"name": "crm",      "tools": ["lookup", "update"]},
         {"name": "payments", "tools": ["refund"]}
       ]}
    ]}

Each agent may instead carry a flat ``tools`` list. Server tools are namespaced as
``<server>.<tool>`` so two servers exposing a same-named tool don't collide.

Where the manifest comes from: an MCP client/host config, an agent-framework definition
(LangChain / Semantic Kernel / AutoGen tool lists), or an agent's registered plugins/connectors
in Copilot Studio or Microsoft Agent 365 / Entra Agent ID. For live MCP servers, the tool list is
what a ``tools/list`` call returns.
"""

from __future__ import annotations

import sys

from .common import emit, read_input, record


def _agent_tools(agent: dict) -> list[str]:
    tools: list[str] = list(agent.get("tools") or [])
    for srv in (agent.get("servers") or []):
        server = srv.get("name") or srv.get("server") or "server"
        for t in (srv.get("tools") or []):
            tools.append(f"{server}.{t}")
    seen: set[str] = set()
    deduped: list[str] = []
    for t in tools:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def transform(config) -> list[dict]:
    agents = config.get("agents", config) if isinstance(config, dict) else config
    out: list[dict] = []
    for a in agents:
        out.append(record(
            id=a.get("id") or a.get("name"),
            name=a.get("name") or a.get("id"),
            type="ai_agent",
            owner=a.get("owner"),
            environment=a.get("environment") or "prod",
            privilege=a.get("privilege") or "scoped",
            credential=a.get("credential"),
            autonomous=bool(a.get("autonomous", False)) or None,
            scopes=a.get("scopes") or None,
            tools=_agent_tools(a) or None,
        ))
    return out


def main(argv: list[str]) -> int:
    emit(transform(read_input(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
