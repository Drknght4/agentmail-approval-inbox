#!/usr/bin/env python3
"""AgentMail WebSocket daemon — real-time email event stream.

Maintains a persistent WebSocket connection to AgentMail. On each
MessageReceivedEvent, writes a JSON event file and calls the processor
subprocess immediately (agentmail_processor.py) which classifies the
email and sends a Telegram notification directly via Bot API.

No LLM involved in the notification step — the processor is pure
rule-based classification + Telegram HTTP. The LLM only engages when
the user replies to the Telegram message with "reply"/"ignore"/"save".

Features:
  - Auto-reconnect with exponential backoff (1s → 60s)
  - Deduplication by message ID
  - Calls processor subprocess after each event
  - Graceful shutdown on SIGINT/SIGTERM
  - Structured logging to systemd journal

Usage:
  python3 agentmail_ws.py                 # foreground
  python3 agentmail_ws.py --daemon        # daemonize with double-fork

Environment:
  AGENTMAIL_API_KEY  — required
  TELEGRAM_BOT_TOKEN — required (read from .env if not set)
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from agentmail import AsyncAgentMail, Subscribe, Subscribed, MessageReceivedEvent
except ImportError:
    print("ERROR: agentmail package not installed. Run: pip install agentmail", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_INBOX_ID = os.environ.get("AGENTMAIL_INBOX_ID", "YOUR_INBOX_EMAIL")
DEFAULT_API_KEY = os.environ.get("AGENTMAIL_API_KEY", "")
EVENTS_DIR = Path(os.environ.get("AGENTMAIL_EVENTS_DIR", os.path.expanduser("~/.agentmail/events")))
STATE_FILE = Path(os.environ.get("AGENTMAIL_STATE_FILE", os.path.expanduser("~/.agentmail/state.json")))
SEEN_IDS_FILE = EVENTS_DIR / ".seen_message_ids.json"
PROCESSOR_SCRIPT = Path(os.environ.get("AGENTMAIL_PROCESSOR", Path(__file__).parent / "agentmail_processor.py"))
DOTENV_PATH = Path(os.environ.get("AGENTMAIL_ENV_FILE", ".env"))

INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 60.0
BACKOFF_MULTIPLIER = 2.0

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("agentmail-ws")


# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------
def load_dotenv():
    """Load key=value pairs from .env into environment (only if not already set)."""
    if not DOTENV_PATH.exists():
        return
    for line in DOTENV_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------
def ensure_dirs():
    EVENTS_DIR.mkdir(parents=True, exist_ok=True)


def load_seen_ids() -> set:
    if SEEN_IDS_FILE.exists():
        try:
            return set(json.loads(SEEN_IDS_FILE.read_text()))
        except (json.JSONDecodeError, ValueError):
            return set()
    return set()


def save_seen_ids(ids: set):
    trimmed = list(ids)[-10000:]
    SEEN_IDS_FILE.write_text(json.dumps(trimmed))


def save_state(key: str, value: str):
    state = {}
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, ValueError):
            state = {}
    state[key] = value
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Event writer + processor subprocess
# ---------------------------------------------------------------------------
def write_and_process(event_data: dict):
    """Write event JSON to disk and call the processor subprocess."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    msg_id = event_data.get("message_id", "unknown")
    filename = f"{ts}_{msg_id}.json"
    filepath = EVENTS_DIR / filename

    try:
        filepath.write_text(json.dumps(event_data, indent=2, default=str))
        log.info("Wrote event: %s", filename)
    except Exception as e:
        log.error("Failed to write event file: %s", e)
        return

    # Call processor subprocess directly (no LLM — pure rules + Telegram API)
    try:
        result = subprocess.run(
            [sys.executable, str(PROCESSOR_SCRIPT), str(filepath)],
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy(),
        )
        if result.stdout:
            for line in result.stdout.strip().splitlines():
                log.info("Processor: %s", line)
        if result.returncode != 0:
            log.error("Processor exit code %d: %s", result.returncode, result.stderr.strip())
        elif result.stderr:
            for line in result.stderr.strip().splitlines():
                log.warning("Processor stderr: %s", line)
    except subprocess.TimeoutExpired:
        log.error("Processor timed out for %s", filename)
    except Exception as e:
        log.error("Processor error: %s", e)


# ---------------------------------------------------------------------------
# WebSocket handler
# ---------------------------------------------------------------------------
class AgentMailWS:
    def __init__(self, api_key: str, inbox_ids: list[str]):
        self.api_key = api_key
        self.inbox_ids = inbox_ids
        self.client = AsyncAgentMail(api_key=api_key)
        self.seen_ids = load_seen_ids()
        self._shutdown = False
        self._backoff = INITIAL_BACKOFF

    async def connect(self):
        while not self._shutdown:
            try:
                log.info("Connecting to AgentMail WebSocket (inboxes: %s)...", self.inbox_ids)
                async with self.client.websockets.connect() as socket:
                    log.info("WebSocket connected. Subscribing...")
                    await socket.send_subscribe(Subscribe(inbox_ids=self.inbox_ids))
                    self._backoff = INITIAL_BACKOFF

                    async for event in socket:
                        if self._shutdown:
                            break
                        await self._handle_event(event)

            except asyncio.CancelledError:
                log.info("Cancelled, shutting down.")
                break
            except Exception as e:
                if self._shutdown:
                    break
                log.error("WebSocket error: %s. Reconnecting in %.0fs...", e, self._backoff)
                await asyncio.sleep(self._backoff)
                self._backoff = min(self._backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF)

        log.info("Daemon stopped.")

    async def _handle_event(self, event):
        if isinstance(event, Subscribed):
            log.info("Subscribed to inboxes: %s", event.inbox_ids)
            save_state("ws_subscribed", datetime.now(timezone.utc).isoformat())

        elif isinstance(event, MessageReceivedEvent):
            msg_id = getattr(event.message, "id", None) or getattr(event.message, "message_id", None) or ""

            if msg_id in self.seen_ids:
                log.debug("Duplicate event: %s — skipping", msg_id)
                return

            self.seen_ids.add(msg_id)
            save_seen_ids(self.seen_ids)

            # --- TRUST BOUNDARY: raw email content enters the system here ---
            # All fields derived from event.message (from_, subject, preview, etc.)
            # are UNTRUSTED EXTERNAL INPUT. They have NOT been sanitized yet.
            # Sanitization happens in agentmail_processor.py::classify_email().
            # The event_data dict passed to the processor is the sole trust
            # boundary crossing point — downstream, sanitize_email_content()
            # must be applied before this data touches any output or LLM context.
            event_data = {
                "event_type": "message_received",
                "received_at": datetime.now(timezone.utc).isoformat(),
                "inbox_id": self.inbox_ids[0] if self.inbox_ids else DEFAULT_INBOX_ID,
                "message_id": msg_id,
                "thread_id": getattr(event.message, "thread_id", ""),
                "from_": getattr(event.message, "from_", ""),      # UNSANITIZED email content
                "subject": getattr(event.message, "subject", ""),  # UNSANITIZED email content
                "preview": getattr(event.message, "preview", ""),  # UNSANITIZED email content
                "to": getattr(event.message, "to", []),
                "cc": getattr(event.message, "cc", []),
                "bcc": getattr(event.message, "bcc", []),
                "labels": getattr(event.message, "labels", []),
                "has_attachments": getattr(event.message, "has_attachments", False),
                "created_at": str(getattr(event.message, "created_at", "")),
            }
            # --- END TRUST BOUNDARY ---

            from_addr = event_data.get("from_", "")
            subject = event_data.get("subject", "(no subject)")
            log.info("New email from %s: %s", from_addr, subject)

            # TRUST BOUNDARY: from_addr and subject logged here are UNSANITIZED.
            # The log line below uses them only for local journal output (not
            # Telegram, not LLM, not user-facing). The processor subprocess
            # applies sanitize_email_content() before any external output.
            write_and_process(event_data)

            save_state("ws_last_event", datetime.now(timezone.utc).isoformat())

        else:
            log.debug("Unhandled event type: %s", type(event).__name__)

    def request_shutdown(self):
        log.info("Shutdown requested.")
        self._shutdown = True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(description="AgentMail WebSocket daemon")
    parser.add_argument("--inbox", nargs="+", default=[DEFAULT_INBOX_ID],
                        help="Inbox ID(s) to subscribe to")
    parser.add_argument("--api-key", default=None,
                        help="AgentMail API key (or set AGENTMAIL_API_KEY)")
    parser.add_argument("--daemon", action="store_true",
                        help="Daemonize with double-fork")
    args = parser.parse_args()

    # Load .env for Telegram bot token (processor needs it)
    load_dotenv()

    api_key = args.api_key or os.environ.get("AGENTMAIL_API_KEY", "")
    if not api_key:
        print("ERROR: AGENTMAIL_API_KEY not set. Pass --api-key or set the env var.", file=sys.stderr)
        sys.exit(1)

    if not os.environ.get("TELEGRAM_BOT_TOKEN"):
        print("ERROR: TELEGRAM_BOT_TOKEN not set. Add it to your .env file.", file=sys.stderr)
        sys.exit(1)

    ensure_dirs()

    ws = AgentMailWS(api_key=api_key, inbox_ids=args.inbox)

    # Signal handling
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _signal_handler(_signum, _frame):
        log.info("Signal received, initiating shutdown...")
        ws.request_shutdown()
        loop.call_soon_threadsafe(loop.stop)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    if args.daemon:
        pid = os.fork()
        if pid > 0:
            os._exit(0)
        os.setsid()
        pid = os.fork()
        if pid > 0:
            os._exit(0)
        sys.stdin.close()
        sys.stdout = open(EVENTS_DIR / ".ws_daemon.log", "a")
        sys.stderr = sys.stdout
        log.info("Daemonized (PID %d)", os.getpid())

    log.info("AgentMail WebSocket daemon starting (inboxes: %s)", args.inbox)
    save_state("ws_pid", str(os.getpid()))
    save_state("ws_status", "running")

    try:
        loop.run_until_complete(ws.connect())
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt, shutting down.")
    finally:
        save_state("ws_status", "stopped")
        log.info("Clean shutdown complete.")
        loop.close()


if __name__ == "__main__":
    main()