"""
AI-Specific Security Checks for MCP Servers

These checks are unique to MCP / LLM tool-use environments. Generic web security
scanners don't look for them because they only matter when a language model is
consuming the server's output or being influenced by its metadata.

Three checks are implemented:

  MCP-AI-001  Tool Description Poisoning
    Tool descriptions are sent to the LLM as part of the system context. A
    malicious server (or a compromised/misconfigured one) can embed prompt
    injection instructions in those descriptions to manipulate the model's
    behaviour, exfiltrate data, or override safety guidelines.

  MCP-AI-002  Over-Permissive Tool Input Schema
    Tools that accept unvalidated string input for parameters like 'command',
    'query', or 'code' are trivially exploitable by anyone who can call them.
    A well-designed MCP tool constrains its inputs with JSON Schema (enums,
    patterns, maxLength). Absence of these constraints widens the attack surface
    for injection attacks.

  MCP-AI-003  Indirect Prompt Injection Risk
    Tools that fetch external URLs or read arbitrary file paths introduce a
    second injection channel: the content they retrieve can contain adversarial
    instructions that the LLM will follow. This is called indirect prompt
    injection — the attack payload isn't in the tool call itself but in the
    content the tool returns.
"""

import sys
from pathlib import Path
from typing import Optional, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils.logger import get_logger

logger = get_logger("ai_specific")


# ──────────────────────────────────────────────────────────────────────────────
# Pattern libraries
# ──────────────────────────────────────────────────────────────────────────────

# Phrases in tool descriptions that suggest an attempt to manipulate the LLM.
# Each entry is a lowercase substring; we check against description.lower().
#
# Organised by attack type so reviewers can easily add or remove patterns.
_POISON_PATTERNS = {
    # Direct instruction override — the attacker tries to cancel the system prompt
    "instruction_override": [
        "ignore previous instructions",
        "ignore all previous",
        "disregard your instructions",
        "disregard the above",
        "forget your instructions",
        "override your instructions",
        "bypass your guidelines",
        "ignore your guidelines",
        "do not follow",
        "stop following",
    ],
    # Role / identity manipulation
    "role_manipulation": [
        "you are now",
        "act as if you are",
        "pretend to be",
        "your new role is",
        "roleplay as",
        "you must now",
        "from now on you",
        "new persona:",
    ],
    # Raw prompt injection delimiters used in various model prompt formats
    "injection_delimiters": [
        "[inst]",
        "[/inst]",
        "<<sys>>",
        "<</sys>>",
        "<|system|>",
        "<|user|>",
        "<|assistant|>",
        "###system",
        "###instruction",
        "system prompt:",
        "system message:",
    ],
    # Exfiltration — instructions to send data to an attacker-controlled endpoint
    "exfiltration": [
        "send all",
        "exfiltrate",
        "leak the",
        "forward the conversation",
        "post the user",
        "transmit the",
    ],
}

# Flatten to a single list for efficient scanning, keeping the category for
# evidence reporting.
_FLAT_POISON_PATTERNS: List[tuple] = [
    (pattern, category)
    for category, patterns in _POISON_PATTERNS.items()
    for pattern in patterns
]

# Parameter names that indicate a tool accepts data that the LLM will later read.
# These create an indirect prompt injection channel when the parameter accepts
# untrusted external content (URLs, file paths, user-supplied text).
_INDIRECT_INJECTION_URL_PARAMS = {
    "url", "uri", "endpoint", "link", "href", "source", "feed",
    "remote", "fetch_url", "target_url", "webhook",
}
_INDIRECT_INJECTION_FILE_PARAMS = {
    "path", "file", "filepath", "filename", "file_path", "document",
}

# Parameter names where a tool accepts a high-risk, unconstrained string.
# 'command', 'code', 'script' with no schema constraints are almost always
# exploitable. 'query' is serious for SQL/NoSQL tools.
_HIGH_RISK_PARAM_NAMES = {
    "command", "cmd", "code", "script", "eval", "exec",
    "query", "sql", "statement",
}


# ──────────────────────────────────────────────────────────────────────────────
# Check 1: Tool description poisoning
# ──────────────────────────────────────────────────────────────────────────────

async def check_tool_poisoning(server: MCPServer) -> Optional[Vulnerability]:
    """
    Scan tool descriptions for prompt injection / poisoning patterns.

    Why this matters: the LLM sees tool descriptions as trusted system context.
    Embedding adversarial instructions there lets an attacker control the model
    without touching the application layer — the model will follow the embedded
    instructions as if they came from the legitimate system prompt.

    We return the first confirmed poisoned tool; if the scan finds multiple,
    the analyst should re-run with verbose logging to see all of them.
    """
    if not server.tool_descriptions:
        # No descriptions available — server didn't return metadata.
        # We can't flag what we can't see, but this isn't itself a vulnerability.
        return None

    confirmed_poison: List[dict] = []

    for tool_name, description in server.tool_descriptions.items():
        if not description:
            continue

        desc_lower = description.lower()
        for pattern, category in _FLAT_POISON_PATTERNS:
            if pattern in desc_lower:
                confirmed_poison.append({
                    "tool": tool_name,
                    "pattern": pattern,
                    "category": category,
                    "snippet": _extract_snippet(description, pattern),
                })
                logger.warning(
                    f"Poison pattern '{pattern}' ({category}) found in tool '{tool_name}'"
                )
                break  # one match per tool is enough for the evidence list

    if not confirmed_poison:
        return None

    evidence = [
        f"Tool '{p['tool']}': found '{p['pattern']}' ({p['category']}) — \"{p['snippet']}\""
        for p in confirmed_poison
    ]

    # CRITICAL if any tool has exfiltration instructions (active data theft).
    # HIGH for other poisoning patterns (model manipulation, instruction override).
    is_critical = any(p["category"] == "exfiltration" for p in confirmed_poison)

    return Vulnerability.create(
        id="MCP-AI-001",
        title="Tool Description Poisoning Detected",
        description=(
            f"The MCP server at {server.url} has {len(confirmed_poison)} tool(s) "
            "whose descriptions contain prompt injection patterns. Because LLMs treat "
            "tool descriptions as trusted system context, this allows an attacker to "
            "override instructions, manipulate the model's behaviour, or exfiltrate "
            "data without any user interaction."
        ),
        severity=Severity.CRITICAL if is_critical else Severity.HIGH,
        category="AI Security",
        remediation=(
            "Remove adversarial content from tool descriptions:\n"
            "- Audit all tool descriptions for instruction-override language\n"
            "- Treat tool descriptions as untrusted if loaded from external sources\n"
            "- Use a static allowlist of approved tool descriptions\n"
            "- Log and alert on unexpected description changes between deployments\n"
            "- Consider a prompt injection detection layer before passing tool "
            "metadata to the LLM"
        ),
        evidence=evidence,
        affected_component="Tool Metadata",
        cwe_id="CWE-77",   # Improper Neutralisation of Special Elements in a Command
        cvss_score=9.1 if is_critical else 7.5,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Check 2: Over-permissive input schema
# ──────────────────────────────────────────────────────────────────────────────

async def check_overpermissive_schema(server: MCPServer) -> Optional[Vulnerability]:
    """
    Identify tools whose inputSchema places no meaningful constraints on input.

    An over-permissive schema means the server trusts the caller to pass safe
    values — but callers are not always trustworthy, and the LLM itself can be
    manipulated into passing attacker-controlled strings. Tight schemas (enums,
    patterns, maxLength) are the first line of defence against injection.

    We flag two patterns:
      a) Tools with no inputSchema at all (accept any JSON object)
      b) Tools with high-risk parameter names (command, query, code, script)
         that have type 'string' but no enum, pattern, or maxLength constraint
    """
    if not server.tools:
        return None

    no_schema: List[str] = []
    unconstrained_high_risk: List[dict] = []

    for tool_name in server.tools:
        schema = server.tool_schemas.get(tool_name, {})

        # Pattern a: no schema at all
        if not schema or schema == {"type": "object"}:
            no_schema.append(tool_name)
            continue

        # Pattern b: high-risk parameter with no constraints
        properties = schema.get("properties", {})
        for param_name, param_schema in properties.items():
            if param_name.lower() not in _HIGH_RISK_PARAM_NAMES:
                continue
            if param_schema.get("type") != "string":
                continue

            # A string parameter is "constrained" if it has at least one of:
            # enum (only specific values), pattern (regex), or maxLength (size limit)
            is_constrained = any(
                k in param_schema for k in ("enum", "pattern", "maxLength")
            )
            if not is_constrained:
                unconstrained_high_risk.append({
                    "tool": tool_name,
                    "param": param_name,
                })

    if not no_schema and not unconstrained_high_risk:
        return None

    evidence = []
    for t in no_schema:
        evidence.append(f"Tool '{t}': no inputSchema — accepts any arguments")
    for item in unconstrained_high_risk:
        evidence.append(
            f"Tool '{item['tool']}': parameter '{item['param']}' is an unconstrained string"
        )

    return Vulnerability.create(
        id="MCP-AI-002",
        title="Over-Permissive Tool Input Schema",
        description=(
            f"The MCP server at {server.url} exposes {len(no_schema)} tool(s) with no "
            f"input schema and {len(unconstrained_high_risk)} tool(s) with high-risk "
            "parameters that accept any string value. Without schema constraints the "
            "server relies entirely on the caller to pass safe input — a single prompt "
            "injection or compromised client can pass arbitrary payloads."
        ),
        severity=Severity.MEDIUM,
        category="AI Security",
        remediation=(
            "Add JSON Schema constraints to all tool inputs:\n"
            "- Use 'enum' for parameters with a fixed set of valid values\n"
            "- Use 'pattern' (regex) for structured strings (IDs, paths)\n"
            "- Use 'maxLength' to prevent oversized inputs\n"
            "- Mark sensitive parameters as not accepting free-form text\n"
            "- Validate inputs server-side even when a schema is published"
        ),
        evidence=evidence,
        affected_component="Tool Input Validation",
        cwe_id="CWE-20",   # Improper Input Validation
        cvss_score=5.3,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Check 3: Indirect prompt injection risk
# ──────────────────────────────────────────────────────────────────────────────

async def check_indirect_injection_risk(server: MCPServer) -> Optional[Vulnerability]:
    """
    Identify tools that fetch external content (URLs, files) and return it to the LLM.

    When a tool fetches a URL or reads a file, the content it returns becomes
    part of the LLM's context. An attacker who controls that content can embed
    adversarial instructions — the LLM will follow them as if they came from a
    trusted source. This is indirect prompt injection.

    We flag tools that have URL-type or file-type parameters because they are
    the primary delivery mechanism for this attack. We don't need to test the
    tool at runtime — the parameter name alone is sufficient evidence of risk.
    """
    if not server.tools:
        return None

    url_risk: List[dict] = []
    file_risk: List[dict] = []

    for tool_name in server.tools:
        schema = server.tool_schemas.get(tool_name, {})
        properties = schema.get("properties", {}) if schema else {}

        for param_name in properties:
            param_lower = param_name.lower()
            if param_lower in _INDIRECT_INJECTION_URL_PARAMS:
                url_risk.append({"tool": tool_name, "param": param_name})
            elif param_lower in _INDIRECT_INJECTION_FILE_PARAMS:
                file_risk.append({"tool": tool_name, "param": param_name})

    # Also check tool names if we have no schemas — tools named 'fetch_url',
    # 'read_file', etc. are a reasonable heuristic when schema data is absent
    if not server.tool_schemas:
        url_keywords = {"fetch", "browse", "curl", "wget", "http_get", "scrape", "crawl"}
        file_keywords = {"read_file", "load_file", "open_file", "get_file"}
        for tool_name in server.tools:
            tool_lower = tool_name.lower()
            if any(kw in tool_lower for kw in url_keywords):
                url_risk.append({"tool": tool_name, "param": "(inferred from name)"})
            elif any(kw in tool_lower for kw in file_keywords):
                file_risk.append({"tool": tool_name, "param": "(inferred from name)"})

    if not url_risk and not file_risk:
        return None

    evidence = []
    for item in url_risk:
        evidence.append(
            f"Tool '{item['tool']}': parameter '{item['param']}' accepts a URL "
            "(SSRF + indirect prompt injection via fetched content)"
        )
    for item in file_risk:
        evidence.append(
            f"Tool '{item['tool']}': parameter '{item['param']}' accepts a file path "
            "(indirect prompt injection via file content)"
        )

    # URL fetching is higher severity than file reading because it's reachable
    # by remote attackers (they control the content at the URL).
    severity = Severity.HIGH if url_risk else Severity.MEDIUM

    return Vulnerability.create(
        id="MCP-AI-003",
        title="Indirect Prompt Injection Risk via External Content",
        description=(
            f"The MCP server at {server.url} exposes tools that fetch content from "
            "external URLs or file paths and return it to the LLM. An attacker who "
            "controls the fetched content can embed adversarial instructions that the "
            "model will follow — without any direct access to the MCP server itself. "
            "This is known as indirect prompt injection."
        ),
        severity=severity,
        category="AI Security",
        remediation=(
            "Mitigate indirect prompt injection from external content:\n"
            "- Sanitise fetched content before including it in LLM context\n"
            "- Use an allowlist of trusted URLs/domains for URL-fetching tools\n"
            "- Restrict file-reading tools to a sandboxed directory\n"
            "- Add a prompt injection detection layer on tool return values\n"
            "- Clearly label external content as untrusted in the model context\n"
            "- Consider whether the LLM actually needs to see raw fetched content "
            "or whether a structured summary is sufficient"
        ),
        evidence=evidence,
        affected_component="Tool External Content Handling",
        cwe_id="CWE-74",   # Improper Neutralisation of Special Elements in Output
        cvss_score=7.5 if url_risk else 5.5,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _extract_snippet(text: str, pattern: str, context: int = 60) -> str:
    """Return a short snippet of `text` centred around `pattern`."""
    idx = text.lower().find(pattern.lower())
    if idx == -1:
        return text[:context]
    start = max(0, idx - context // 2)
    end = min(len(text), idx + len(pattern) + context // 2)
    snippet = text[start:end].replace("\n", " ").strip()
    return f"...{snippet}..." if start > 0 else f"{snippet}..."
