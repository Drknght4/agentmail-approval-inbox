#!/usr/bin/env python3
"""
ContextQuarantine — Tainted data tracking for the email processing pipeline.

Tracks email-derived content as "tainted" throughout processing. Tainted
data can be summarized for logging but MUST NEVER:
  - Persist to memory or long-term storage
  - Directly influence tool calls or automation decisions
  - Cross quarantine boundaries without explicit taint-level checks

Each tainted context gets a unique quarantine_id for audit tracing.
All quarantine operations are logged to ~/.agentmail/audit/quarantine.jsonl.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Audit log path
# ---------------------------------------------------------------------------
QUARANTINE_AUDIT_DIR = Path.home() / ".agentmail" / "audit"
QUARANTINE_AUDIT_FILE = QUARANTINE_AUDIT_DIR / "quarantine.jsonl"

# Maximum length for safe summaries — enough for logging, not enough for
# full context reconstruction
_SAFE_SUMMARY_MAX_LENGTH = 100


# ===========================================================================#
# TaintedContext — tracks a single piece of tainted email-derived content
# ===========================================================================#

@dataclass
class TaintedContext:
    """A single piece of tainted (email-derived) content being tracked.

    # QUARANTINE BOUNDARY: This dataclass represents untrusted content.
    # It MUST NOT be persisted to memory, stored in long-term state,
    # or used directly to trigger tool calls.
    """

    source: str              # "email_subject", "email_preview", "email_sender", "attachment"
    content: str             # sanitized content (still tainted — source is untrusted)
    taint_level: str         # "low", "medium", "high"
    timestamp: float         # unix epoch when registered
    thread_id: str            # email thread this content came from
    quarantine_id: str        # unique ID for audit tracing

    def to_dict(self) -> dict:
        """Serialize to dict for audit logging."""
        return asdict(self)


# ===========================================================================#
# TaintViolationError — raised when tainted content crosses a boundary
# ===========================================================================#

class TaintViolationError(Exception):
    """Raised when tainted content attempts to cross a quarantine boundary.

    # QUARANTINE BOUNDARY: This error is the enforcement mechanism.
    # It MUST be raised whenever tainted data attempts to:
    #   - Persist to memory or long-term storage
    #   - Directly trigger a tool call or automation action
    #   - Cross into a context where it would influence decisions
    #   without explicit taint-level checks.
    """
    pass


# ===========================================================================#
# ContextQuarantine — tracks tainted data throughout the pipeline
# ===========================================================================#

class ContextQuarantine:
    """Tracks tainted (email-derived) content throughout the processing pipeline.

    # QUARANTINE BOUNDARY: This class enforces the quarantine policy.
    # Tainted content is registered, tracked, and eventually flushed.
    # It can be summarized for logging but MUST NEVER persist to memory,
    # directly trigger tool calls, or influence automation decisions.

    Rules enforced:
      - can_persist() always returns False
      - can_influence_tools() always returns False
      - is_tainted() checks if any registered content matches
      - get_safe_summary() returns truncated, logging-safe string
      - audit_log() records every operation to quarantine.jsonl
      - flush() clears all tainted contexts for a thread
    """

    def __init__(self) -> None:
        # QUARANTINE BOUNDARY: internal state tracking — never persisted
        self._registry: Dict[str, TaintedContext] = {}  # quarantine_id -> TaintedContext
        self._content_index: Dict[str, List[str]] = {}  # thread_id -> [quarantine_id, ...]

    # ------------------------------------------------------------------
    # register — add tainted content to the quarantine
    # ------------------------------------------------------------------
    def register(
        self,
        content: str,
        source: str,
        thread_id: str,
        taint_level: str = "medium",
    ) -> TaintedContext:
        """Register tainted content in the quarantine.

        # QUARANTINE BOUNDARY: content enters the quarantine here.
        # It is assigned a quarantine_id and tracked. From this point,
        # it can be summarized but MUST NOT persist or trigger tools.

        Args:
            content: Sanitized but still untrusted email-derived string.
            source: Origin of the content (e.g. "email_subject").
            thread_id: Email thread this content came from.
            taint_level: Risk level — "low", "medium", or "high".

        Returns:
            TaintedContext with a unique quarantine_id.
        """
        valid_sources = {"email_subject", "email_preview", "email_sender", "attachment"}
        if source not in valid_sources:
            raise ValueError(
                f"Invalid source '{source}'. Must be one of: {valid_sources}"
            )

        valid_levels = {"low", "medium", "high"}
        if taint_level not in valid_levels:
            raise ValueError(
                f"Invalid taint_level '{taint_level}'. Must be one of: {valid_levels}"
            )

        quarantine_id = f"q_{uuid.uuid4().hex[:12]}"

        tainted = TaintedContext(
            source=source,
            content=content,
            taint_level=taint_level,
            timestamp=time.time(),
            thread_id=thread_id,
            quarantine_id=quarantine_id,
        )

        # QUARANTINE BOUNDARY: storing in quarantine — not in memory, not in tools
        self._registry[quarantine_id] = tainted

        if thread_id not in self._content_index:
            self._content_index[thread_id] = []
        self._content_index[thread_id].append(quarantine_id)

        self.audit_log(tainted, action="register")
        return tainted

    # ------------------------------------------------------------------
    # is_tainted — check if a string matches any registered tainted content
    # ------------------------------------------------------------------
    def is_tainted(self, content: str) -> bool:
        """Check if a string contains or matches any registered tainted content.

        # QUARANTINE BOUNDARY: this method checks whether content has been
        # quarantined. A True result means the content is NOT safe to persist
        # or use for tool triggering.

        Args:
            content: String to check against the quarantine registry.

        Returns:
            True if the content matches any registered tainted context.
        """
        if not content:
            return False

        content_lower = content.lower()
        for qid, tainted in self._registry.items():
            # Check for containment — if the tainted content is a substring
            # of the input, or vice versa (partial overlap)
            if tainted.content and (
                tainted.content.lower() in content_lower
                or content_lower in tainted.content.lower()
            ):
                return True
            # Also check for high-similarity overlap (first 30 chars match)
            if len(tainted.content) >= 10 and len(content) >= 10:
                if tainted.content[:30].lower() == content[:30].lower():
                    return True

        return False

    # ------------------------------------------------------------------
    # get_safe_summary — truncated, logging-safe summary
    # ------------------------------------------------------------------
    def get_safe_summary(self, tainted: TaintedContext) -> str:
        """Return a safe, truncated summary of tainted content for logging only.

        # QUARANTINE BOUNDARY: The returned summary is intentionally
        # truncated to prevent full context reconstruction. It is safe
        # for audit logs but MUST NOT be used as input to any tool,
        # memory write, or automation decision.

        Args:
            tainted: The TaintedContext to summarize.

        Returns:
            Truncated string (max 100 chars) safe for logging.
        """
        if len(tainted.content) <= _SAFE_SUMMARY_MAX_LENGTH:
            summary = tainted.content
        else:
            summary = tainted.content[:_SAFE_SUMMARY_MAX_LENGTH - 3] + "..."

        return f"[QUARANTINE:{tainted.quarantine_id}] ({tainted.taint_level}) {tainted.source}: {summary}"

    # ------------------------------------------------------------------
    # can_persist — ALWAYS returns False
    # ------------------------------------------------------------------
    def can_persist(self, tainted: TaintedContext) -> bool:
        """Check whether tainted content can persist to memory/storage.

        # QUARANTINE BOUNDARY: This method ALWAYS returns False.
        # Tainted (email-derived) content must never be persisted to
        # long-term memory, Obsidian vault, or any durable store.

        Returns:
            Always False.
        """
        # QUARANTINE BOUNDARY: enforcement — tainted content never persists
        return False

    # ------------------------------------------------------------------
    # can_influence_tools — ALWAYS returns False
    # ------------------------------------------------------------------
    def can_influence_tools(self, tainted: TaintedContext) -> bool:
        """Check whether tainted content can directly trigger tool calls.

        # QUARANTINE BOUNDARY: This method ALWAYS returns False.
        # Tainted (email-derived) content must never directly cause
        # automation actions, API calls, or state mutations.

        Returns:
            Always False.
        """
        # QUARANTINE BOUNDARY: enforcement — tainted content never triggers tools
        return False

    # ------------------------------------------------------------------
    # audit_log — record quarantine operations
    # ------------------------------------------------------------------
    def audit_log(self, tainted: TaintedContext, action: str) -> None:
        """Log a quarantine operation to the audit file.

        # QUARANTINE BOUNDARY: Audit logs are append-only records.
        # They contain only the safe summary, never the full tainted content.

        Args:
            tainted: The TaintedContext involved in the operation.
            action: The action being logged (e.g. "register", "flush", "violation").
        """
        QUARANTINE_AUDIT_DIR.mkdir(parents=True, exist_ok=True)

        entry = {
            "timestamp": time.time(),
            "quarantine_id": tainted.quarantine_id,
            "action": action,
            "source": tainted.source,
            "taint_level": tainted.taint_level,
            "thread_id": tainted.thread_id,
            "content_preview": tainted.content[:50] if tainted.content else "",
        }

        try:
            with open(QUARANTINE_AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            # Audit logging is best-effort — never block processing
            print(f"QUARANTINE_AUDIT: failed to write audit log: {e}", file=__import__("sys").stderr)

    # ------------------------------------------------------------------
    # flush — clear all tainted contexts for a thread
    # ------------------------------------------------------------------
    def flush(self, thread_id: str) -> int:
        """Clear all tainted contexts for a thread after processing is complete.

        # QUARANTINE BOUNDARY: Flushing removes tainted content from the
        # in-memory registry. This is called after the email has been fully
        # processed (notification sent, action taken) to prevent any
        # residual tainted data from persisting.

        Args:
            thread_id: The email thread whose contexts should be flushed.

        Returns:
            Number of contexts flushed.
        """
        if thread_id not in self._content_index:
            return 0

        quarantine_ids = self._content_index.pop(thread_id)
        flushed = 0

        for qid in quarantine_ids:
            tainted = self._registry.pop(qid, None)
            if tainted:
                self.audit_log(tainted, action="flush")
                flushed += 1

        return flushed

    # ------------------------------------------------------------------
    # get_by_thread — retrieve all tainted contexts for a thread
    # ------------------------------------------------------------------
    def get_by_thread(self, thread_id: str) -> List[TaintedContext]:
        """Get all tainted contexts registered for a specific thread.

        # QUARANTINE BOUNDARY: Returned contexts are still tainted.
        # Use get_safe_summary() for logging; never persist or trigger tools.

        Args:
            thread_id: The email thread to look up.

        Returns:
            List of TaintedContexts for that thread.
        """
        if thread_id not in self._content_index:
            return []

        return [
            self._registry[qid]
            for qid in self._content_index[thread_id]
            if qid in self._registry
        ]

    # ------------------------------------------------------------------
    # check_and_enforce — enforce a boundary, raise if violated
    # ------------------------------------------------------------------
    def check_and_enforce(
        self,
        content: str,
        boundary: str,
        context: str = "",
    ) -> None:
        """Check if content is tainted and raise TaintViolationError if it is.

        # QUARANTINE BOUNDARY: This is the enforcement gate. Call it
        # before any operation that should NOT receive tainted content
        # (e.g. memory writes, tool calls, persistent storage).

        Args:
            content: The content to check.
            boundary: Name of the boundary being enforced (e.g. "memory_persist", "tool_trigger").
            context: Additional context for the error message.

        Raises:
            TaintViolationError: If the content matches any registered tainted context.
        """
        if self.is_tainted(content):
            raise TaintViolationError(
                f"Quarantine boundary violation at '{boundary}': "
                f"tainted content attempted to cross into {context or 'protected zone'}. "
                f"Content: {content[:60]}..."
            )


# ---------------------------------------------------------------------------
# Self-test on direct execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    cq = ContextQuarantine()

    print("=== ContextQuarantine Self-Test ===\n")

    # Test 1: Register tainted content
    t1 = cq.register(
        content="<script>alert('xss')</script>Hello World from attacker",
        source="email_subject",
        thread_id="thread_001",
        taint_level="high",
    )
    assert t1.quarantine_id.startswith("q_")
    assert t1.source == "email_subject"
    assert t1.taint_level == "high"
    print(f"1. Register: PASS — {t1.quarantine_id}")

    # Sanitized version (as ReaderAgent would produce)
    t2 = cq.register(
        content="Hello World from attacker",
        source="email_preview",
        thread_id="thread_001",
        taint_level="medium",
    )
    print(f"2. Register preview: PASS — {t2.quarantine_id}")

    # Test 3: is_tainted
    assert cq.is_tainted("Hello World from attacker")
    assert not cq.is_tainted("Completely unrelated safe content")
    print("3. is_tainted: PASS")

    # Test 4: get_safe_summary
    summary = cq.get_safe_summary(t1)
    assert len(summary) <= 150  # generous limit for the full formatted line
    assert t1.quarantine_id in summary
    assert "high" in summary
    print(f"4. get_safe_summary: PASS — {summary}")

    # Test 5: can_persist always False
    assert cq.can_persist(t1) is False
    assert cq.can_persist(t2) is False
    print("5. can_persist always False: PASS")

    # Test 6: can_influence_tools always False
    assert cq.can_influence_tools(t1) is False
    assert cq.can_influence_tools(t2) is False
    print("6. can_influence_tools always False: PASS")

    # Test 7: check_and_enforce raises TaintViolationError
    try:
        cq.check_and_enforce("Hello World from attacker", boundary="memory_persist")
        print("7. check_and_enforce: FAIL — should have raised")
        sys.exit(1)
    except TaintViolationError as e:
        assert "memory_persist" in str(e)
        print("7. check_and_enforce raises TaintViolationError: PASS")

    # Test 8: check_and_enforce passes for non-tainted content
    try:
        cq.check_and_enforce("Safe content", boundary="memory_persist")
        print("8. check_and_enforce passes for safe content: PASS")
    except TaintViolationError:
        print("8. check_and_enforce: FAIL — should not have raised")
        sys.exit(1)

    # Test 9: get_by_thread
    thread_contexts = cq.get_by_thread("thread_001")
    assert len(thread_contexts) == 2
    print(f"9. get_by_thread: PASS — {len(thread_contexts)} contexts")

    # Test 10: flush
    flushed = cq.flush("thread_001")
    assert flushed == 2
    assert len(cq.get_by_thread("thread_001")) == 0
    print(f"10. flush: PASS — {flushed} contexts flushed")

    # Test 11: Invalid source raises ValueError
    try:
        cq.register(content="test", source="invalid_source", thread_id="t1")
        print("11. Invalid source validation: FAIL — should have raised")
        sys.exit(1)
    except ValueError as e:
        assert "Invalid source" in str(e)
        print("11. Invalid source raises ValueError: PASS")

    # Test 12: Invalid taint_level raises ValueError
    try:
        cq.register(content="test", source="email_subject", thread_id="t1", taint_level="critical")
        print("12. Invalid taint_level validation: FAIL — should have raised")
        sys.exit(1)
    except ValueError as e:
        assert "Invalid taint_level" in str(e)
        print("12. Invalid taint_level raises ValueError: PASS")

    # Test 13: Audit log exists
    assert QUARANTINE_AUDIT_FILE.exists()
    lines = QUARANTINE_AUDIT_FILE.read_text().strip().split("\n")
    assert len(lines) >= 2  # register + flush entries
    print(f"13. Audit log written: PASS — {len(lines)} entries")

    print("\nAll 13 tests passed.")