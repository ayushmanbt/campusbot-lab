"""
mock_llm.py  —  A deterministic, injectable teaching model for the CampusBot lab.

WHY A MOCK?
    A real LLM is stochastic. In a teaching lab you need the attack to succeed
    the same way every time, on every laptop, with no API key and no internet.
    This mock reproduces the ONE property that matters for prompt injection:

        It flattens system + user + retrieved content into a single string and
        then follows the most salient instructions it finds there, regardless of
        which "role" they arrived under.

    That single design choice is the whole vulnerability. Everything the lab
    demonstrates about defence is demonstrated against this faithful stand-in,
    and every *architectural* defence (egress control, capability scoping) is
    real code that would work identically against a frontier model.

HONESTY NOTE (say this to participants):
    The model-layer defences here (spotlighting) are modelled as *reducing*
    obedience, not eliminating it — exactly as they behave in the literature.
    One payload is deliberately built to survive spotlighting, so nobody leaves
    believing a prompt-level trick is a wall. The controls that hold every time
    live OUTSIDE the model, in the application.

An optional real-model backend is included at the bottom for faculty who want
to re-run the same lab against an actual API.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- #
#  Message + response containers
# --------------------------------------------------------------------------- #
@dataclass
class Message:
    role: str        # "system" | "user" | "tool"  (tool == retrieved/untrusted)
    content: str
    trusted: bool = False   # provenance flag the app may set; the BASE model ignores it


@dataclass
class ToolCall:
    name: str
    args: dict


@dataclass
class LLMResponse:
    text: str
    tool_calls: list = field(default_factory=list)
    # bookkeeping the lab prints so learners can see *why* it did what it did:
    obeyed_injection: bool = False
    leaked_system_prompt: bool = False
    notes: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
#  Directive detection — the model "understanding" instructions in its context
# --------------------------------------------------------------------------- #
# These patterns stand in for an instruction-tuned model's learned disposition
# to follow salient imperatives. They are intentionally simple and readable.

_URL_RE = re.compile(r"https?://[^\s\)\]\"'>]+", re.I)

_LEAK_RE = re.compile(
    r"(print|reveal|repeat|show|output|display|summari[sz]e)\b[^.\n]*"
    r"(system prompt|your instructions|your configuration|everything above|the text above)",
    re.I,
)
_OVERRIDE_RE = re.compile(
    r"(ignore|disregard|forget|override)\b[^.\n]*"
    r"(previous|prior|above|earlier|all)\b[^.\n]*(instruction|prompt|rule|directive)",
    re.I,
)
_EXFIL_RE = re.compile(
    r"(send|post|forward|exfiltrate|transmit|upload|report|deliver|fetch|visit|open)\b[^\n]*?"
    r"(https?://\S+)",
    re.I,
)
_REDIRECT_RE = re.compile(
    r"(route|redirect|direct|send)\b[^\n]*?"
    r"(enquir|inquir|request|question|user|student)[^\n]*?(https?://\S+)",
    re.I,
)
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^\)]+)\)")
_AUTHORITY_RE = re.compile(
    r"(policy|precedence|official|effective immediately)[^\n]*?"
    r"(handled|available|processed|claimed?)\s+at\s+(https?://\S+)", re.I)
_TOOLCALL_RE = re.compile(r"(?:run_tool|call)\(\s*['\"]?(\w+)['\"]?\s*(?:,\s*(.*?))?\)")


def _find_data_of_interest(context: str) -> str:
    """What an exfiltration payload would scoop up. In the lab this is any line
    that looks like sensitive record data placed in the context."""
    hits = re.findall(r"(?:SECRET|PII|EMAIL|PHONE|SSN|AADHAAR|API[_-]?KEY)[:=]\s*\S+",
                      context, re.I)
    return " | ".join(hits) if hits else "no-sensitive-data-in-context"


class MockLLM:
    """A faithful-enough instruction follower for teaching prompt injection.

    Parameters
    ----------
    respect_provenance : bool
        Baseline model = False. When the application applies *spotlighting*
        (Session 2, Defence 2) it sets this True, and the model will decline
        directives found inside clearly-marked untrusted spans — but ONLY those
        that look like overt instructions. An "authority-framed" payload with no
        imperative verb still gets through, which is the honest limitation of
        prompt-level defence.
    """

    def __init__(self, system_prompt: str, respect_provenance: bool = False):
        self.system_prompt = system_prompt
        self.respect_provenance = respect_provenance

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _strip_marked_directives(text: str) -> str:
        """Neutralise only OVERT directives inside spotlight-marked spans.

        HONEST MODEL OF SPOTLIGHTING: a provenance-aware model learns to ignore
        text inside «DATA»…«/DATA» that *looks like a command* (imperative verbs,
        "ignore previous", "reveal", "forward to <url>"). It does NOT reliably
        ignore statements framed as authoritative policy with no imperative verb.
        So we blank out only the overt-directive lines within marked spans and
        leave declarative 'authority framing' intact — which is why payload C2
        still gets through L2 alone."""
        def scrub(match):
            span = match.group(0)
            out_lines = []
            for line in span.splitlines():
                overt = re.search(
                    r"\b(ignore|disregard|forget|reveal|print|repeat|show|"
                    r"forward|send|exfiltrate|fetch|post|route|redirect|"
                    r"you are now)\b", line, re.I)
                out_lines.append(" (marked-directive suppressed) " if overt else line)
            return "\n".join(out_lines)
        return re.sub(r"«DATA».*?«/DATA»", scrub, text, flags=re.S)

    # -- the model ---------------------------------------------------------- #
    def generate(self, messages: list) -> LLMResponse:
        # THE VULNERABILITY, IN ONE LINE: everything becomes one string.
        flat = "\n".join(m.content for m in messages)

        # What the model will actually reason over. A spotlighting-aware model
        # ignores directives inside marked untrusted regions (imperfectly).
        reasoning_text = flat
        if self.respect_provenance:
            reasoning_text = self._strip_marked_directives(flat)

        resp = LLMResponse(text="")
        notes = resp.notes

        # PRECEDENCE: high-impact actions first (exfiltration, redirect), then
        # leakage, then explicit tool calls, then the benign path. This mirrors
        # an agent that will *act* if a reachable action is described.

        # 1) Exfiltration via an explicit URL or a markdown image ---------- #
        exfil_url = None
        m = _EXFIL_RE.search(reasoning_text)
        if m:
            u = _URL_RE.search(m.group(0))
            exfil_url = u.group(0) if u else None
        img = _MD_IMAGE_RE.search(reasoning_text)
        if img:
            exfil_url = img.group(1)

        if exfil_url:
            data = _find_data_of_interest(flat)
            sep = "&" if "?" in exfil_url else "?"
            call_url = f"{exfil_url}{sep}d={data.replace(' ', '')}"
            resp.tool_calls.append(ToolCall("fetch_url", {"url": call_url}))
            resp.obeyed_injection = True
            notes.append(f"matched an exfiltration directive -> fetch_url({exfil_url})")
            resp.text = "Here is your summary. [rendering attached resource…]"
            return resp

        # 2) Redirect / phishing link in the answer ----------------------- #
        r = _REDIRECT_RE.search(reasoning_text)
        if r:
            bad_m = _URL_RE.search(r.group(0))
            if bad_m:
                bad = bad_m.group(0)
                resp.obeyed_injection = True
                notes.append(f"matched a redirect directive -> phishing link {bad}")
                resp.text = ("To claim your refund, please use the official portal here: "
                             f"{bad}\n(As per the latest revised policy.)")
                return resp

        # 2b) Authority-framed redirect (survives spotlighting) ---------- #
        a = _AUTHORITY_RE.search(reasoning_text)
        if a:
            bad_m = _URL_RE.search(a.group(0))
            if bad_m:
                bad = bad_m.group(0)
                resp.obeyed_injection = True
                notes.append(f"followed authority-framed policy -> link {bad}")
                resp.text = ("As per official university policy, refund enquiries "
                             f"are handled here: {bad}")
                return resp

        # 3) System-prompt leakage ---------------------------------------- #
        if _LEAK_RE.search(reasoning_text):
            resp.leaked_system_prompt = True
            resp.obeyed_injection = True
            notes.append("matched a system-prompt-leak directive")
            resp.text = ("Sure — here is my configuration:\n"
                         f"<<<SYSTEM PROMPT>>>\n{self.system_prompt}\n<<<END>>>")
            return resp

        # 4) Explicit tool-call syntax in the context --------------------- #
        t = _TOOLCALL_RE.search(reasoning_text)
        if t:
            name = t.group(1)
            raw = (t.group(2) or "").strip().strip("'\"")
            resp.tool_calls.append(ToolCall(name, {"arg": raw}))
            resp.obeyed_injection = True
            notes.append(f"matched an explicit tool call -> {name}({raw})")
            resp.text = f"Executing requested step ({name})…"
            return resp

        # 5) Benign path: answer from the retrieved context --------------- #
        answer = self._summarise(messages)
        resp.text = answer
        notes.append("no injection matched; answered from retrieved context")
        return resp

    @staticmethod
    def _summarise(messages: list) -> str:
        """A stand-in for helpful behaviour: echo a short summary of the first
        retrieved (tool) document, or fall back to a generic reply."""
        for m in messages:
            if m.role == "tool" and m.content.strip():
                first = m.content.strip().splitlines()
                headline = next((l for l in first if l.strip()), "")
                return ("Based on the campus documents: "
                        + headline.strip("# ").strip()
                        + " (ask me for specifics).")
        return "I can help with admissions, library and refund questions."


# --------------------------------------------------------------------------- #
#  OPTIONAL: real-model backend (faculty extension — needs a key + internet)
# --------------------------------------------------------------------------- #
class RealLLM:
    """Drop-in replacement that calls a real API. Not used in the offline lab.
    Kept minimal and dependency-light; wire in your provider of choice."""

    def __init__(self, system_prompt: str, model: str = "your-model-id"):
        self.system_prompt = system_prompt
        self.model = model

    def generate(self, messages: list) -> LLMResponse:  # pragma: no cover
        raise NotImplementedError(
            "Fill in a real API call here to re-run the lab against a live model.\n"
            "The point of the lab holds either way: the architectural defences in\n"
            "campusbot_secure.py sit OUTSIDE the model and work regardless of backend."
        )
