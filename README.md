# AgentMail Approval Inbox

A real-time email approval system that classifies incoming emails, sends Telegram notifications with interactive buttons, and only engages an LLM when you take action — zero AI tokens spent on notifications.

Built with [AgentMail](https://agentmail.to), [Hermes Agent](https://hermes-agent.nousresearch.com), and the Telegram Bot API.

## How It Works

```
AgentMail Cloud
  ↓ WebSocket (wss://) — instant push, no polling
  ↓ MessageReceivedEvent
agentmail_ws.py          ← systemd service: agentmail-ws
  │   Persists connection, subscribes to inbox
  │   Writes JSON event file
  │   Calls processor as subprocess
  ↓
agentmail_processor.py   ← subprocess, ZERO LLM
  │   Classifies: 🔴 approval / 🔵 personal / 🟡 transactional / ⚪ newsletter / ⚫ spam
  │   Stores action mapping in pending_actions.json (short keys)
  │   Sends Telegram notification via Bot API (inline buttons)
  │   Moves event to .processed/
  ↑
User taps: ✅ Reply | 🗑️ Ignore | 📝 Save
  ↓ callback_data: am:<action>:<short_key>
  ↓
Hermes Agent (LLM)       ← only now, only on Reply/Save
  │   Reads thread via MCP tools
  │   Drafts reply or saves to Obsidian vault
  │   Always CCs owner + includes signature
```

## Key Design Goals

- **Zero LLM cost for notifications** — classification and Telegram delivery use pure Python
- **Instant delivery** — WebSocket push, not polling
- **Human-in-the-loop** — no auto-replies, ever
- **Three actions per email**: Reply, Ignore, Save

## Classification Heuristics

| Classification | Signals | Suggested Action |
|---|---|---|
| 🔴 **approval** | Subject: "request", "approval", "pending", "action required", "review", "signature", "urgent" | Reply |
| 🔵 **personal** | Human sender, no spam/newsletter signals | Reply |
| 🟡 **transactional** | Receipt, invoice, confirmation, shipping, verification, password reset | Save |
| ⚪ **newsletter** | noreply/no-reply sender, "unsubscribe" in body, "weekly/digest" in subject | Ignore |
| ⚫ **spam** | Marketing keywords + newsletter signals | Ignore |

Attachments always upgrade the action to at least "save".

## Prerequisites

| Requirement | Details |
|---|---|
| Python 3.11+ | With `agentmail` and `websockets` packages |
| AgentMail Account | [console.agentmail.to](https://console.agentmail.to) (free tier: 3 inboxes) |
| AgentMail API Key | From AgentMail console |
| Telegram Bot Token | From [@BotFather](https://t.me/BotFather) |
| Telegram Chat ID | From [@userinfobot](https://t.me/userinfobot) |
| Systemd | Linux user-level services |
| Hermes Agent (optional) | For LLM-powered Reply/Save actions via MCP tools |

## Quick Start

### 1. Install Python Dependencies

```bash
pip install agentmail websockets
```

### 2. Configure Environment

Copy the example env file and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env` with your actual values:

```ini
AGENTMAIL_API_KEY=am_us_your_key_here
TELEGRAM_BOT_TOKEN=123456789:ABCdef_your_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
AGENTMAIL_INBOX_ID=your-inbox@agentmail.to
OBSIDIAN_VAULT=~/obsidian-vault
```

### 3. Test in Foreground

```bash
# Terminal 1: Start the WebSocket daemon
python3 agentmail_ws.py --inbox your-inbox@agentmail.to

# Terminal 2: Send yourself a test email, watch the notification arrive
```

### 4. Install as a systemd Service

```bash
# Copy the service file
mkdir -p ~/.config/systemd/user
cp agentmail-ws.service ~/.config/systemd/user/

# Edit paths and credentials in the service file
nano ~/.config/systemd/user/agentmail-ws.service

# Reload, enable, start
systemctl --user daemon-reload
systemctl --user enable agentmail-ws
systemctl --user start agentmail-ws

# Verify
systemctl --user status agentmail-ws
journalctl --user -u agentmail-ws -f
```

## Short Key System

Telegram's `callback_data` is limited to 64 bytes. AgentMail message IDs can exceed 80 bytes alone. The processor stores full thread/message IDs in `pending_actions.json` and uses short keys like `n1`, `n2` in the callback:

```json
{
  "n1": {
    "thread_id": "8b559cf6-a19f-41b6-bf95-12bf68c2b296",
    "message_id": "<long-message-id@example.com>"
  }
}
```

Callback: `am:reply:n1` → 10 bytes. Well under the 64-byte limit.

## Telegram Notification Example

```
✉️ New Email — Quarterly Budget Review
From: Finance Team
Subject: Q3 Budget Review 📎
Preview: Please review the attached spreadsheet and approve...
Classified: approval
[✅ Reply]  [🗑️ Ignore]  [📝 Save]
```

## Project Structure

```
agentmail-approval-inbox/
├── agentmail_ws.py            # WebSocket daemon — persistent AgentMail connection
├── agentmail_processor.py     # Event processor — classification + Telegram notification + sanitization
├── agentmail-ws.service       # systemd user service file
├── agentmail-approval/
│   └── SKILL.md               # Hermes Agent skill definition
├── tests/
│   └── test_security.py       # 89 unit tests — injection, escaping, attachment safety
├── .env.example               # Environment variable template
├── README.md                  # This file
├── SECURITY.md                # Trust boundaries, sanitization flow, injection risks
└── LICENSE                    # MIT License
```

> **Note:** Default paths use `~/.agentmail/`. If you are running Hermes Agent, adjust paths to `~/.hermes/agentmail_events/` to match your setup.

## Security Considerations

- **Never commit real credentials.** API keys, bot tokens, and chat IDs belong in `.env` only.
- **Telegram callback authorization.** The handler verifies the button-tapper is an authorized user before processing.
- **Minimal data over Telegram.** Only sender, subject, preview, and classification are sent — never the full email body.
- **Local-first storage.** Email content is only stored locally in `~/.agentmail/events/.processed/`.
- **Callback TTL.** Pending actions (short keys for Telegram callbacks) expire after 48 hours. Stale entries are purged automatically on each processor run.
- **Input sanitization.** All email-derived content (subjects, previews, sender fields) passes through a sanitization pipeline before reaching Telegram, Obsidian vault, or LLM context. See [SECURITY.md](SECURITY.md) for the full trust boundary model and sanitization flow.
- **Prompt injection defense.** All email-derived content is sanitized before reaching any LLM or output system. See [SECURITY.md](SECURITY.md) for the full trust boundary architecture.
- **89 unit tests** cover injection scenarios, attachment safety, and output escaping.
- **Set restrictive file permissions on event storage directories.** Example for Hermes-integrated deployments:

```bash
chmod 700 ~/.hermes/agentmail_events
chmod 600 ~/.hermes/agentmail_seen_threads.json
```

Default paths use `~/.agentmail/` — adjust to match your actual deployment.

## AgentMail MCP Configuration (Hermes Agent)

To enable LLM-powered Reply/Save actions, add the AgentMail MCP server to your Hermes config:

```yaml
mcp:
  servers:
    agentmail:
      command: npx
      args: ["-y", "agentmail-mcp"]
      env:
        AGENTMAIL_API_KEY: "YOUR_AGENTMAIL_API_KEY"
```

## Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| No notifications | `systemctl --user status agentmail-ws` | Restart: `systemctl --user restart agentmail-ws` |
| WebSocket not connecting | `journalctl --user -u agentmail-ws` | Verify API key in `.env` |
| Buttons don't work | Gateway logs for `am:` callbacks | Verify `pending_actions.json` exists |
| Callback data too long | `BUTTON_DATA_INVALID` in Telegram | Ensure short keys (`n1`, `n2`) are used |
| Email sent but no notification | Self-send doesn't trigger WebSocket | Send from a different address to test |
| Processor fails silently | `ls ~/.agentmail/events/.processed/` | Check `TELEGRAM_BOT_TOKEN` in environment |

## License

MIT — Nova AI. Use freely, share openly, keep your secrets secret.