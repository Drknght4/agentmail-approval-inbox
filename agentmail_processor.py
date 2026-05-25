#!/usr/bin/env python3
"""AgentMail Event Processor — classifies emails and sends Telegram notifications.

Called by agentmail_ws.py as a subprocess after each MessageReceivedEvent.
Zero LLM involvement — pure rule-based classification and Telegram Bot API calls.

Usage:
  python3 agentmail_processor.py <event_file.json>

Environment:
  TELEGRAM_BOT_TOKEN  — required
  TELEGRAM_CHAT_ID    — required (default: YOUR_TELEGRAM_CHAT_ID)
  OBSIDIAN_VAULT      — default: ~/obsidian-vault
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "YOUR_TELEGRAM_CHAT_ID")
TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
OBSIDIAN_VAULT = Path(os.environ.get("OBSIDIAN_VAULT", os.path.expanduser("~/obsidian-vault")))
NOTES_DIR = OBSIDIAN_VAULT / "Notes" / "Email"
PROCESSED_DIR = Path(os.environ.get(
    "AGENTMAIL_EVENTS_DIR",
    os.path.expanduser("~/.agentmail/events"),
)) / ".processed"
PENDING_ACTIONS_FILE = Path(os.environ.get(
    "AGENTMAIL_EVENTS_DIR",
    os.path.expanduser("~/.agentmail/events"),
)) / "pending_actions.json"


# ---------------------------------------------------------------------------
# Classification (from Approval Inbox template heuristics)
# ---------------------------------------------------------------------------
def classify_email(event: dict) -> dict:
    """Classify an email and produce metadata for notification."""
    from_ = event.get("from_", "Unknown")
    subject = event.get("subject", "(no subject)")
    preview = event.get("preview", "")
    has_attachments = event.get("has_attachments", False)

    subject_lower = subject.lower()
    preview_lower = preview.lower()
    from_lower = from_.lower()

    # Spam signals
    spam_words = ["unsubscribe", "opt out", "discount code", "limited time",
                  "act now", "congratulations", "free trial"]
    is_spam = any(w in preview_lower for w in spam_words) and any(
        kw in subject_lower for kw in ["newsletter", "weekly", "digest", "update", "report"]
    )

    # Newsletter signals
    newsletter_senders = ["substack", "mailer", "newsletter", "noreply", "no-reply",
                          "notifications@", "news@", "digest"]
    is_newsletter = (
        any(ns in from_lower for ns in newsletter_senders) or
        "unsubscribe" in preview_lower or
        any(kw in subject_lower for kw in ["weekly", "daily digest", "newsletter", "roundup"])
    )

    # Transactional signals
    transactional_kw = ["receipt", "invoice", "confirmation", "order", "shipping",
                        "delivery", "payment", "statement", "verification", "welcome to",
                        "your account", "password reset", "2fa", "one-time code",
                        "verify your", "security alert"]
    is_transactional = any(kw in subject_lower for kw in transactional_kw)

    # Approval signals
    approval_kw = ["request", "approval", "approve", "pending", "action required",
                   "needs your", "review", "signature", "sign ", "please review",
                   "urgent", "asap", "time-sensitive"]
    is_approval = any(kw in subject_lower for kw in approval_kw)

    # Classify
    if is_spam:
        cls, action, emoji = "spam", "ignore", "⚫"
    elif is_approval:
        cls, action, emoji = "approval", "reply", "🔴"
    elif is_transactional:
        if has_attachments:
            cls, action, emoji = "transactional", "save", "🟡"
        else:
            cls, action, emoji = "transactional", "ignore", "🟡"
    elif is_newsletter:
        if has_attachments:
            cls, action, emoji = "newsletter", "save", "⚪"
        else:
            cls, action, emoji = "newsletter", "ignore", "⚪"
    else:
        cls, action, emoji = "personal", "reply", "🔵"

    sender_name = from_.split("<")[0].strip() if "<" in from_ else from_
    summary = f"✉️ **New Email** — {subject[:70]}"
    if len(subject) > 70:
        summary = summary[:73] + "...**"

    return {
        "classification": cls,
        "action": action,
        "emoji": emoji,
        "from_": from_,
        "sender_name": sender_name,
        "subject": subject,
        "preview": preview[:200],
        "has_attachments": has_attachments,
        "thread_id": event.get("thread_id", ""),
        "message_id": event.get("message_id", ""),
        "inbox_id": event.get("inbox_id", ""),
        "received_at": event.get("received_at", ""),
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Telegram Bot API — direct HTTP, no SDK
# ---------------------------------------------------------------------------
def send_telegram(text: str, chat_id: str = TELEGRAM_CHAT_ID,
                  reply_markup: dict | None = None) -> bool:
    """Send a message via Telegram Bot API. Returns True on success."""
    if not TELEGRAM_BOT_TOKEN:
        print("ERROR: TELEGRAM_BOT_TOKEN not set", file=sys.stderr)
        return False

    url = f"{TELEGRAM_API}/sendMessage"
    payload_dict = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }
    if reply_markup:
        payload_dict["reply_markup"] = reply_markup

    payload = json.dumps(payload_dict).encode("utf-8")

    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("ok"):
                msg_id = result.get("result", {}).get("message_id")
                print(f"Telegram sent: message_id={msg_id}")
                return True
            else:
                print(f"Telegram API error: {result}", file=sys.stderr)
                return False
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"Telegram HTTP error {e.code}: {body}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Telegram error: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Pending actions store (short callback data for Telegram's 64-byte limit)
# ---------------------------------------------------------------------------
def _load_pending() -> dict:
    """Load the pending actions store."""
    if PENDING_ACTIONS_FILE.exists():
        try:
            return json.loads(PENDING_ACTIONS_FILE.read_text())
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def _save_pending(store: dict):
    """Save the pending actions store."""
    PENDING_ACTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PENDING_ACTIONS_FILE.write_text(json.dumps(store, indent=2))


def _store_action(thread_id: str, message_id: str) -> str:
    """Store thread_id/message_id and return a short key like 'n42'."""
    store = _load_pending()
    # Find next numeric key
    next_id = max((int(k[1:]) for k in store if k.startswith("n")), default=0) + 1
    key = f"n{next_id}"
    store[key] = {"thread_id": thread_id, "message_id": message_id}
    _save_pending(store)
    return key


# ---------------------------------------------------------------------------
# Notification format
# ---------------------------------------------------------------------------
def format_notification(c: dict) -> tuple[str, dict]:
    """Format a Telegram notification message and inline keyboard."""
    attach_str = " 📎" if c["has_attachments"] else ""

    lines = [
        c["summary"],
        f"**From:** {c['sender_name']}",
        f"**Subject:** {c['subject']}{attach_str}",
    ]
    if c["preview"]:
        preview = c["preview"][:160]
        if len(c["preview"]) > 160:
            preview += "..."
        lines.append(f"**Preview:** {preview}")
    lines.append(f"**Classified:** {c['classification']}")

    text = "\n".join(lines)

    # Store action data and use short keys for Telegram's 64-byte callback_data limit
    key = _store_action(c["thread_id"], c["message_id"])

    # Inline keyboard with three action buttons (callback_data ≤ 64 bytes)
    keyboard = {
        "inline_keyboard": [[
            {"text": "✅ Reply", "callback_data": f"am:reply:{key}"},
            {"text": "🗑️ Ignore", "callback_data": f"am:ignore:{key}"},
            {"text": "📝 Save", "callback_data": f"am:save:{key}"},
        ]]
    }

    return text, keyboard


# ---------------------------------------------------------------------------
# Save to Obsidian vault
# ---------------------------------------------------------------------------
def save_to_vault(c: dict, event: dict) -> str | None:
    """Save email as a Markdown note in Obsidian vault. Returns file path or None."""
    NOTES_DIR.mkdir(parents=True, exist_ok=True)

    safe_subject = "".join(ch if ch.isalnum() or ch in " -_" else "_" for ch in c["subject"][:60]).strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    filename = f"{ts}_{safe_subject}.md"
    filepath = NOTES_DIR / filename

    content = f"""---
title: "Email: {c['subject']}"
date: "{c['received_at']}"
source: agentmail
from: "{c['from_']}"
classification: {c['classification']}
thread_id: "{c['thread_id']}"
message_id: "{c['message_id']}"
tags: [email, {c['classification']}]
---

# {c['subject']}

**From:** {c['from_']}
**Received:** {c['received_at']}
**Classification:** {c['classification']}

## Preview

{event.get('preview', 'No preview available.')}

---

*Auto-processed by AgentMail Processor*
"""
    try:
        filepath.write_text(content)
        return str(filepath)
    except Exception as e:
        print(f"ERROR saving to vault: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: agentmail_processor.py <event_file.json>", file=sys.stderr)
        sys.exit(1)

    event_path = Path(sys.argv[1])
    if not event_path.exists():
        print(f"ERROR: event file not found: {event_path}", file=sys.stderr)
        sys.exit(1)

    try:
        event = json.loads(event_path.read_text())
    except (json.JSONDecodeError, ValueError) as e:
        print(f"ERROR: failed to parse event: {e}", file=sys.stderr)
        sys.exit(1)

    if event.get("event_type") != "message_received":
        print(f"Skipping non-message event: {event.get('event_type', 'unknown')}")
        # Still move to processed
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        dest = PROCESSED_DIR / event_path.name
        event_path.rename(dest)
        sys.exit(0)

    # Classify
    classified = classify_email(event)

    # Format and send Telegram notification with inline buttons
    notification, keyboard = format_notification(classified)
    success = send_telegram(notification, reply_markup=keyboard)

    if success:
        print(f"NOTIFIED: {classified['classification']} email from {classified['sender_name']} — {classified['subject'][:50]}")
    else:
        print(f"FAILED to notify: {classified['subject'][:50]}", file=sys.stderr)

    # Move to processed
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    dest = PROCESSED_DIR / event_path.name
    try:
        event_path.rename(dest)
        print(f"PROCESSED: {event_path.name} → {dest.name}")
    except Exception as e:
        print(f"ERROR moving to processed: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()