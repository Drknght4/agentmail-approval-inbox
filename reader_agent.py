#!/usr/bin/env python3
"""
ReaderAgent — Tool-less email event reader.

Receives raw email event data and returns structured, sanitized output.
NO tool access, NO filesystem writes, NO MCP calls, NO HTTP requests.
Its only job is to read and return structured data.
"""

from __future__ import annotations

import importlib
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Import sanitization from the standalone sanitizer module (no circular import)
# ---------------------------------------------------------------------------
from sanitizer import sanitize_email_content


# ===========================================================================#
# ReaderOutput — structured, sanitized result
# ===========================================================================#

@dataclass
class ReaderOutput:
    """Structured output from the ReaderAgent.

    All fields contain sanitized content — no raw unsanitized data.
    """

    from_address: str
    sender_name: str
    subject: str
    preview: str
    has_attachments: bool
    thread_id: str
    message_id: str
    inbox_id: str
    received_at: str
    raw_sanitized: Dict[str, Any]  # all sanitized fields in one dict
    read_timestamp: float


# ===========================================================================#
# ReaderAgent — tool-less reader
# ===========================================================================#

# NO TOOLS — this class must never import or use: requests, urllib,
# subprocess, os.system, mcp, hermes tool modules, or any I/O library.
# SecurityError is raised if any forbidden import is detected.

_FORBIDDEN_MODULES = {
    "requests",
    "urllib3",
    "urllib.request",
    "subprocess",
    "os",       # os.system / os.popen are I/O vectors
    "mcp",
    "hermes_tools",
}

_FORBIDDEN_ATTRS = {
    # os.system, os.popen are I/O vectors but os.path is read-only
    ("os", "system"),
    ("os", "popen"),
}


class SecurityError(Exception):
    """Raised when the module contains forbidden tool-level imports."""


class ReaderAgent:
    """Tool-less reader agent.

    Receives raw email event data and returns a ReaderOutput with all
    fields sanitized.  It has:
      - NO tool access
      - NO filesystem writes
      - NO MCP calls
      - NO HTTP requests

    Its only job is to read and return structured data.
    """

    # NO TOOLS — do not add requests, urllib, subprocess, os.system,
    # mcp, or hermes tool imports to this class or its methods.

    def read(self, event: dict) -> ReaderOutput:
        """Read a raw email event, sanitize all fields, return structured output.

        # NO TOOLS — this method must never perform I/O, network calls,
        # or filesystem writes beyond reading its input dict.

        Args:
            event: Raw email event dict from the AgentMail WebSocket or API.
                   Supports both camelCase (from AgentMail API) and snake_case
                   (from agentmail_ws.py) field names.

        Returns:
            ReaderOutput with all text fields sanitized and no raw content.
        """
        from_raw = str(event.get("from_", "") or event.get("from", "") or "")
        sender_name_raw = str(event.get("senderName", "") or event.get("sender_name", "") or "")
        subject_raw = str(event.get("subject", "") or "")
        preview_raw = str(event.get("preview", "") or event.get("bodyPreview", "") or "")
        thread_id = str(event.get("threadId", "") or event.get("thread_id", "") or "")
        message_id = str(event.get("messageId", "") or event.get("message_id", "") or "")
        inbox_id = str(event.get("inboxId", "") or event.get("inbox_id", "") or "")
        received_at = str(event.get("receivedAt", "") or event.get("received_at", "") or "")
        has_attachments = bool(event.get("hasAttachments", False) or event.get("has_attachments", False))

        # Sanitize all text fields
        from_address = sanitize_email_content(from_raw, field_name="from")
        sender_name = sanitize_email_content(sender_name_raw, field_name="sender_name")
        subject = sanitize_email_content(subject_raw, field_name="subject")
        preview = sanitize_email_content(preview_raw, field_name="preview")

        # Build raw_sanitized — all sanitized fields in one dict
        raw_sanitized: Dict[str, Any] = {
            "from": from_address,
            "sender_name": sender_name,
            "subject": subject,
            "preview": preview,
            "has_attachments": has_attachments,
            "thread_id": thread_id,
            "message_id": message_id,
            "inbox_id": inbox_id,
            "received_at": received_at,
        }

        return ReaderOutput(
            from_address=from_address,
            sender_name=sender_name,
            subject=subject,
            preview=preview,
            has_attachments=has_attachments,
            thread_id=thread_id,
            message_id=message_id,
            inbox_id=inbox_id,
            received_at=received_at,
            raw_sanitized=raw_sanitized,
            read_timestamp=time.time(),
        )

    @classmethod
    def validate_no_tools(cls) -> None:
        """Verify this module has no forbidden tool-level imports.

        Raises SecurityError if any module in _FORBIDDEN_MODULES is found
        in sys.modules that was imported by reader_agent.py, or if any
        forbidden attribute access is detected.
        """
        # Get the modules imported by this file
        this_module = sys.modules.get(__name__)
        if this_module is None:
            return

        module_attrs = dir(this_module)

        # Check for forbidden top-level modules
        for mod_name in _FORBIDDEN_MODULES:
            # Allow os.path but flag bare os (which gives access to os.system)
            if mod_name == "os":
                # Check if 'os' is a visible name in this module's namespace
                if "os" in module_attrs:
                    os_mod = getattr(this_module, "os")
                    # If it's the real os module (not just os.path), flag it
                    if hasattr(os_mod, "system"):
                        raise SecurityError(
                            f"Forbidden import detected: 'os' module exposes "
                            f"os.system/os.popen I/O vectors. "
                            f"ReaderAgent must remain tool-less."
                        )
                continue

            if mod_name in module_attrs:
                raise SecurityError(
                    f"Forbidden import detected: '{mod_name}' is not allowed "
                    f"in ReaderAgent. Tool-less design requires no I/O capability."
                )

        # Check for forbidden attribute usage
        for attr_name in module_attrs:
            for forbidden_mod, forbidden_attr in _FORBIDDEN_ATTRS:
                if attr_name == forbidden_attr:
                    raise SecurityError(
                        f"Forbidden attribute detected: {forbidden_mod}.{forbidden_attr} "
                        f"is not allowed in ReaderAgent."
                    )


# ---------------------------------------------------------------------------
# Self-test on direct execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    agent = ReaderAgent()

    # Validate no tools
    try:
        agent.validate_no_tools()
        print("✅ Security check passed — no forbidden imports")
    except SecurityError as e:
        print(f"❌ Security check FAILED: {e}")
        sys.exit(1)

    # Test read with sample event (using agentmail_ws snake_case field names)
    sample_event = {
        "from_": "attacker@example.com",
        "subject": "<script>alert('xss')</script>Hello",
        "preview": "Click [here](https://evil.com) for free stuff http://track.com/?utm_source=spam",
        "thread_id": "thread_123",
        "message_id": "msg_456",
        "inbox_id": "inbox_789",
        "received_at": "2026-05-28T21:00:00Z",
        "has_attachments": False,
        "sender_name": "Fake Bank <security@fake.com>",
    }

    output = agent.read(sample_event)
    print(f"\n--- ReaderOutput ---")
    print(f"from_address: {output.from_address}")
    print(f"sender_name:  {output.sender_name}")
    print(f"subject:      {output.subject}")
    print(f"preview:      {output.preview}")
    print(f"has_attachments: {output.has_attachments}")
    print(f"thread_id:    {output.thread_id}")
    print(f"message_id:   {output.message_id}")
    print(f"inbox_id:     {output.inbox_id}")
    print(f"received_at:  {output.received_at}")
    print(f"read_timestamp: {output.read_timestamp}")
    print(f"\nraw_sanitized keys: {list(output.raw_sanitized.keys())}")

    # Verify sanitization worked
    assert "<script>" not in output.subject, "Subject not sanitized!"
    assert "evil.com" not in output.preview, "Preview links not sanitized!"
    assert "utm_source" not in output.preview, "Tracking params not stripped!"
    print("\n✅ Sanitization assertions passed")