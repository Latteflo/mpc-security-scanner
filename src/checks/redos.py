"""
Regular Expression Denial of Service (ReDoS) Check

MCP-DOS-002  ReDoS via Tool Input Validated with Backtracking Regex

  If a tool validates its inputs using a regex with catastrophic backtracking
  (e.g. (a+)+ or (w+s?)*, a crafted input can cause the validation step
  to consume CPU exponentially, effectively hanging the server.

  Detection strategy:
    1. Extract `pattern` constraints from tool JSON Schemas.
    2. Identify patterns that exhibit the structural hallmarks of catastrophic
       backtracking: nested quantifiers, alternation inside a repeated group,
       or overlapping character classes.
    3. Generate a worst-case input for each suspicious pattern and measure the
       round-trip time of a tool call that would trigger the validation.
    4. If the response takes significantly longer than the server's baseline,
       flag as confirmed ReDoS.

  We cap the probe input length and the timeout at safe values so this check
  itself cannot DoS the target.
"""

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("redos")

# Regex structural patterns that can backtrack catastrophically.
# Each is a compiled Python regex that matches *descriptions* of risky patterns.
_RISKY_PATTERNS: list[tuple[str, str]] = [
    # Nested quantifiers: (X+)+ or (X*)* or (X+)*
    (r"\([^)]*[+*][^)]*\)[+*?]", "nested quantifier"),
    # Alternation with overlap inside a quantifier: (a|ab)+
    (r"\([^)]*\|[^)]*\)[+*?]", "alternating group with quantifier"),
    # Greedy repetition of groups containing \\w or \\d etc.
    (r"\(\\\\[wdWDs][^)]*\)[+*]", "character-class group with quantifier"),
    # Back-reference inside quantifier (can cause exponential backtracking)
    (r"\\\\[0-9][+*?]", "back-reference with quantifier"),
]

_COMPILED_RISKY = [(re.compile(p), label) for p, label in _RISKY_PATTERNS]

# How many 'a' characters to send as the catastrophic input
_REDOS_INPUT_LENGTH = 30   # safe: detectable delay without long hang

# Baseline probe — a trivially non-matching string
_BASELINE_INPUT = "safe_input_xyz"

# Round-trip threshold that signals delay (seconds above baseline)
_DELAY_THRESHOLD_S = 2.0

# Hard ceiling for individual probes so we don't hang
_PROBE_TIMEOUT_S = 8.0


def _is_risky_pattern(pattern: str) -> str | None:
    """Return a risk label if the pattern has catastrophic-backtracking structure, else None."""
    for compiled, label in _COMPILED_RISKY:
        if compiled.search(pattern):
            return label
    return None


def _worst_case_input(pattern: str, length: int = _REDOS_INPUT_LENGTH) -> str:
    """
    Generate a worst-case input for a backtracking regex.
    Strategy: extract the first repeated character class / literal and
    produce a long string of it followed by a non-matching character.
    """
    # Extract a likely repeated character
    m = re.search(r"\(([^)]{1,5})\)[+*]", pattern)
    if m:
        inner = m.group(1).replace("\\w", "a").replace("\\d", "1").replace("\\s", " ")
        char = inner[0] if inner else "a"
    else:
        char = "a"
    return char * length + "!"


async def _timed_call(server_url: str, tool: str, param: str, value: str) -> float:
    """Return wall-clock seconds for a tool call, or inf on error."""
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool, "arguments": {param: value}},
        "id": 1,
    }
    t0 = time.monotonic()
    try:
        await asyncio.wait_for(
            http_post(server_url, request, timeout=_PROBE_TIMEOUT_S),
            timeout=_PROBE_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        return time.monotonic() - t0
    except Exception:
        return 0.0
    return time.monotonic() - t0


async def check_redos(server: MCPServer) -> Optional[Vulnerability]:
    """Check for ReDoS vulnerabilities in tool input schema regex patterns."""
    if not server.tools:
        return None

    schemas = getattr(server, "tool_schemas", {}) or {}
    confirmed: list[tuple[str, str, str, float]] = []  # (tool, param, label, delay)

    for tool in server.tools:
        schema = schemas.get(tool, {})
        props = (
            schema.get("properties")
            or schema.get("inputSchema", {}).get("properties")
            or {}
        )

        for param, defn in props.items():
            if not isinstance(defn, dict):
                continue
            pattern = defn.get("pattern")
            if not pattern:
                continue

            risk_label = _is_risky_pattern(pattern)
            if not risk_label:
                continue

            logger.debug(f"Suspicious pattern in {tool}.{param}: {pattern!r} ({risk_label})")

            # Measure baseline
            baseline = await _timed_call(server.url, tool, param, _BASELINE_INPUT)

            # Measure worst-case
            worst = _worst_case_input(pattern)
            attack_time = await _timed_call(server.url, tool, param, worst)

            delay = attack_time - baseline
            if delay >= _DELAY_THRESHOLD_S:
                confirmed.append((tool, param, risk_label, delay))
                logger.warning(f"ReDoS confirmed: {tool}.{param} — {delay:.1f}s delay")
                break   # one confirmed finding per tool is enough

    if not confirmed:
        return None

    tool, param, label, delay = confirmed[0]

    return Vulnerability.create(
        id="MCP-DOS-002",
        title=f"ReDoS Vulnerability in Tool Input Validation ({tool}.{param})",
        description=(
            f"The parameter '{param}' of tool '{tool}' on {server.url} uses a regex "
            f"pattern with {label} that causes catastrophic backtracking. A crafted "
            f"input produced a {delay:.1f}s server-side delay, confirming that an "
            "attacker can hang the server with a single tool call."
        ),
        severity=Severity.HIGH,
        category="Availability",
        remediation=(
            "Fix ReDoS vulnerabilities:\n"
            "- Rewrite the regex to eliminate nested quantifiers and overlapping alternatives\n"
            "- Use atomic groups or possessive quantifiers where the regex engine supports them\n"
            "- Enforce a maximum input length before applying the regex\n"
            "- Use a linear-time regex engine (e.g. Google RE2 / Python `re2` binding)\n"
            "- Add a server-side timeout on all input validation operations"
        ),
        evidence=[
            f"Vulnerable tool: {tool}",
            f"Parameter: {param}",
            f"Pattern type: {label}",
            f"Response delay: {delay:.1f}s (threshold: {_DELAY_THRESHOLD_S}s)",
        ] + [f"Additional: {t}.{p} ({lb})" for t, p, lb, _ in confirmed[1:3]],
        affected_component=f"Tool: {tool}",
        cwe_id="CWE-1333",
        cvss_score=7.5,
    )
