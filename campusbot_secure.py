"""
campusbot_secure.py  —  The HARDENED agent for Session 2.

Same app, same corpus, same teaching model — with the five layers switched on
individually so participants can see the effect of each, and then all together.

Toggle any layer via the SecureConfig flags. The lab drives these toggles to
reproduce the table on the "Would it have worked?" slide.
"""

from __future__ import annotations
import os
import re
import glob
from dataclasses import dataclass, field

from mock_llm import MockLLM, Message
from defenses import (
    sanitize_untrusted, spotlight, detect_injection,
    EgressAllowList, EgressBlocked,
    require_confirmation, ConfirmationRequired,
)

# NOTE: the secret has been REMOVED from the system prompt (Session 2, fix 0).
# Authorisation for the records service now lives in the application layer,
# where it is a deterministic check the model cannot disclose or override.
SECURE_SYSTEM_PROMPT = (
    "You are CampusBot, the student assistant for Adamas University. "
    "Answer questions using only the provided campus documents. "
    "Be concise and helpful."
)

ALLOWED_EGRESS = ["adamasuniversity.ac.in", "cdn.adamasuniversity.ac.in"]


@dataclass
class SecureConfig:
    sanitize: bool = True          # L1
    spotlight: bool = True         # L2
    detect: bool = True            # L3
    egress_allowlist: bool = True  # L4
    scope_tools: bool = True       # L5a: drop tools a Q&A bot does not need
    confirm_actions: bool = True   # L5b: human approval for consequential actions
    answer_url_allowlist: bool = True  # L4-sibling: strip non-approved URLs from the answer


@dataclass
class SecureResult:
    answer: str
    tool_log: list = field(default_factory=list)
    blocked: list = field(default_factory=list)     # controls that fired
    alerts: list = field(default_factory=list)      # detection telemetry
    obeyed_injection: bool = False
    leaked_system_prompt: bool = False
    model_notes: list = field(default_factory=list)


class SecureCampusBot:
    def __init__(self, corpus_dir: str, config: SecureConfig | None = None):
        self.corpus_dir = corpus_dir
        self.cfg = config or SecureConfig()
        # L2: a spotlighting-aware model instance when the layer is on.
        self.llm = MockLLM(SECURE_SYSTEM_PROMPT,
                           respect_provenance=self.cfg.spotlight)
        self.egress = EgressAllowList(ALLOWED_EGRESS)
        self.attacker_server_log = []

    def retrieve(self, query: str, k: int = 1) -> list:
        docs = []
        for path in sorted(glob.glob(os.path.join(self.corpus_dir, "*.md"))):
            text = open(path, encoding="utf-8").read()
            score = sum(text.lower().count(w) for w in query.lower().split())
            docs.append((score, path, text))
        docs.sort(reverse=True, key=lambda d: d[0])
        return [(p, t) for _, p, t in docs[:k]]

    # -- tools, now guarded ------------------------------------------------ #
    def _fetch_url(self, url: str, result: SecureResult):
        if self.cfg.egress_allowlist:
            try:
                self.egress.check(url)                       # L4: deterministic gate
            except EgressBlocked as e:
                result.blocked.append(str(e))
                return "[egress blocked]"
        self.attacker_server_log.append(url)                 # only if allowed
        return f"[fetched {url}]"

    def _write_file(self, path: str, content: str, result: SecureResult):
        if self.cfg.confirm_actions:
            try:
                require_confirmation("write_file",
                                     {"path": path, "bytes": len(content)},
                                     approver=None)           # L5b: auto-deny in lab
            except ConfirmationRequired as e:
                result.blocked.append(str(e))
                return "[write requires confirmation — denied]"
        return f"[wrote {len(content)} bytes to {path}]"

    def _run_tool(self, call, result: SecureResult):
        # L5a: capability scoping. A Q&A assistant is not granted fetch/write.
        if self.cfg.scope_tools and call.name in ("fetch_url", "write_file"):
            result.blocked.append(
                f"tool '{call.name}' not in this agent's scope (capability scoping)")
            return
        if call.name == "fetch_url":
            eff = self._fetch_url(call.args.get("url", ""), result)
            result.tool_log.append(("fetch_url", call.args.get("url", ""), eff))
        elif call.name == "write_file":
            eff = self._write_file(call.args.get("path", "out.txt"),
                                   call.args.get("arg", ""), result)
            result.tool_log.append(("write_file", call.args, eff))

    # -- pipeline ---------------------------------------------------------- #
    def ask(self, user_query: str) -> SecureResult:
        retrieved = self.retrieve(user_query)
        result = SecureResult(answer="")

        messages = [Message("system", SECURE_SYSTEM_PROMPT, trusted=True),
                    Message("user", user_query, trusted=True)]

        for path, text in retrieved:
            clean = text
            if self.cfg.sanitize:                            # L1
                clean = sanitize_untrusted(text)
            if self.cfg.detect:                              # L3 (telemetry)
                d = detect_injection(clean)
                if d["flagged"]:
                    result.alerts.append({"doc": os.path.basename(path),
                                          "hits": d["hits"]})
            if self.cfg.spotlight:                           # L2
                clean = spotlight(clean)
            messages.append(Message("tool", clean, trusted=False))

        resp = self.llm.generate(messages)
        answer = resp.text
        if self.cfg.answer_url_allowlist:
            def _strip(m):
                host = re.sub(r"^https?://", "", m.group(0)).split("/")[0].lower()
                if host in self.egress.allowed:
                    return m.group(0)
                result.blocked.append(f"answer URL to '{host}' removed (not approved)")
                return "[link removed by policy]"
            answer = re.sub(r"https?://[^\s\)]+", _strip, answer)
        result.answer = answer
        result.obeyed_injection = resp.obeyed_injection
        result.leaked_system_prompt = resp.leaked_system_prompt
        result.model_notes = resp.notes
        for call in resp.tool_calls:
            self._run_tool(call, result)
        return result


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    bot = SecureCampusBot(os.path.join(here, "corpus"))
    r = bot.ask("How do I claim a refund?")
    print("ANSWER :", r.answer)
    print("BLOCKED:", r.blocked)
    print("ALERTS :", r.alerts)
