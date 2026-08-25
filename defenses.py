"""
defenses.py  —  The five defence layers, as small composable functions.

Grouped exactly as the FDP deck groups them:

    PROBABILISTIC  (reduce risk; evadable by an adaptive attacker)
        L1  sanitize_untrusted   — strip hidden text / invisible characters
        L2  spotlight            — mark untrusted spans so the model down-weights them
        L3  detect_injection     — heuristic classifier (telemetry, not a wall)

    DETERMINISTIC  (bound the worst case; hold regardless of the payload)
        L4  EgressAllowList      — only approved destinations may receive data
        L5  capability scoping   — the agent simply is not granted the tool
            + require_confirmation for consequential actions

The teaching point the lab drives home: L1–L3 sometimes fail in the demo, on
purpose. L4–L5 never do, because they do not depend on the model's decision.
"""

from __future__ import annotations
import re
import unicodedata
from urllib.parse import urlparse


# =========================================================================== #
#  L1  —  INGESTION HYGIENE : strip hidden text and invisible characters
# =========================================================================== #
# Real techniques covered: HTML comments, zero-width chars, the Unicode Tag
# block (U+E0000–U+E007F), bidi overrides, and colour/font concealment markers.

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060], None       # ZWSP ZWNJ ZWJ BOM WJ
)
_BIDI = dict.fromkeys(
    [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069], None
)
# Marker our lab documents use to simulate "white text on white" concealment:
_WHITE_TEXT = re.compile(r"\[\[HIDDEN\]\].*?\[\[/HIDDEN\]\]", re.S)


def _strip_unicode_tags(s: str) -> str:
    """Remove the Unicode Tag block used for invisible smuggling."""
    return "".join(ch for ch in s if not (0xE0000 <= ord(ch) <= 0xE007F))


def sanitize_untrusted(text: str) -> str:
    """L1: return only what a human would actually see, normalised.

    Deterministic and cheap. Eliminates the entire 'hidden text' subclass —
    which is how most of the document-based cases in the deck were planted.
    """
    text = _HTML_COMMENT.sub(" ", text)
    text = _WHITE_TEXT.sub(" ", text)
    text = _strip_unicode_tags(text)
    text = text.translate(_ZERO_WIDTH)
    text = text.translate(_BIDI)
    text = unicodedata.normalize("NFKC", text)
    return text


def diff_hidden(original: str) -> str:
    """Diagnostic: show what sanitisation removed (the 'render vs extract' test)."""
    cleaned = sanitize_untrusted(original)
    removed = []
    for pat, label in [(_HTML_COMMENT, "html-comment"),
                       (_WHITE_TEXT, "white-text"),]:
        removed += [f"[{label}] {m.group(0)[:80]}" for m in pat.finditer(original)]
    tags = [ch for ch in original if 0xE0000 <= ord(ch) <= 0xE007F]
    if tags:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tags)
        removed.append(f"[unicode-tag] {decoded[:80]}")
    return "\n".join(removed) if removed else "(nothing hidden found)"


# =========================================================================== #
#  L2  —  SPOTLIGHTING : mark untrusted spans so the model treats them as data
# =========================================================================== #
def spotlight(untrusted_text: str) -> str:
    """L2: wrap untrusted content in an unambiguous data boundary.

    In this lab the MockLLM, when run with respect_provenance=True, will decline
    overt directives found inside «DATA»…«/DATA». Honest caveat: a payload with
    no imperative verb (pure authority framing) still slips through — demonstrated
    live in Session 2. Prompt-level defence reduces; it does not eliminate.
    """
    return f"«DATA»{untrusted_text}«/DATA»"


# =========================================================================== #
#  L3  —  DETECTION : a heuristic classifier for telemetry / volume reduction
# =========================================================================== #
_SIGNATURES = [
    re.compile(r"ignore\s+(all\s+)?previous", re.I),
    re.compile(r"disregard\s+(prior|above|earlier)", re.I),
    re.compile(r"(reveal|print|repeat)\s+.*(system prompt|instructions)", re.I),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"(send|forward|exfiltrate).*https?://", re.I),
]


def detect_injection(text: str) -> dict:
    """L3: return {'flagged': bool, 'hits': [...]}.

    Useful: reduces volume, produces the alert that tells you you're under
    attack. NOT a wall: it is trained on the *scaffolding* of known payloads,
    so payload-splitting and novel phrasing evade it (shown in Session 2).
    """
    hits = [p.pattern for p in _SIGNATURES if p.search(text)]
    return {"flagged": bool(hits), "hits": hits}


# =========================================================================== #
#  L4  —  EGRESS ALLOW-LISTING : the highest-value deterministic control
# =========================================================================== #
class EgressBlocked(Exception):
    """Raised when the agent tries to reach a non-approved destination."""


class EgressAllowList:
    """L4: only approved hosts may receive an outbound request.

    Deterministic. Works no matter what the model decided, in any language, for
    any encoding. This is the control that stops the *breach* even after the
    *injection* has already succeeded.
    """

    def __init__(self, allowed_hosts):
        self.allowed = set(h.lower() for h in allowed_hosts)
        self.log = []            # every decision, for the lab to print

    def check(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        ok = host in self.allowed
        self.log.append((url, host, "ALLOW" if ok else "BLOCK"))
        if not ok:
            raise EgressBlocked(
                f"Egress to '{host}' refused (not on allow-list {sorted(self.allowed)})"
            )
        return True


# =========================================================================== #
#  L5  —  CAPABILITY SCOPING + HUMAN CONFIRMATION
# =========================================================================== #
class ConfirmationRequired(Exception):
    """Raised when a consequential action needs explicit human approval."""


def require_confirmation(action: str, params: dict, approver=None):
    """L5b: gate an irreversible/external action behind a human decision.

    `approver` is a callable returning True/False. In the lab we default to
    auto-DENY so the demo is deterministic; a real deployment shows the params
    to a person. The point: the model can *request* the action, but cannot
    *cause* it without a trusted authority saying yes.
    """
    decision = False if approver is None else bool(approver(action, params))
    if not decision:
        raise ConfirmationRequired(
            f"Action '{action}' with {params} was NOT approved by a human."
        )
    return True
