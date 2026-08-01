# AgentMail Callback Handler Patch

## Problem

The Hermes gateway's Telegram adapter handles inline keyboard callbacks with prefixes like `gt:`, `ea:`, `sc:`, `cp:`, `mp:`, and `cl:` — but it had no handler for `am:` callbacks from the AgentMail approval inbox.

When a user pressed Reply, Ignore, Save, or Trust Sender on an AgentMail Telegram notification, the callback was silently dropped. The notification was edited (buttons stripped) but no action was taken.

## Solution

Added an `am:` callback handler to the Telegram adapter that:

1. Parses `am:action:key` callback data
2. Verifies user authorization
3. Looks up the short key in `pending_actions.json`
4. Enforces one-time-use consumption
5. For `reply`/`save`: creates a synthetic `MessageEvent` and dispatches it through `self.handle_message()` — the same path real incoming messages take. The agent receives the thread details and processes the email via AgentMail MCP tools.
6. For `trust`: calls `handle_trust_callback()` from the processor module
7. For `ignore`: edits the message and strips the keyboard

## Patch Location

The patch modifies:
`~/.hermes/hermes-agent/plugins/platforms/telegram/adapter.py`

Two additions:

### 1. Callback routing (in `_handle_callback_query` method)

Added before the `sc:` handler:

```python
# --- AgentMail approval callbacks (am:action:key) ---
if data.startswith("am:"):
    await self._handle_agentmail_callback(
        query,
        data,
        query_chat_id=query_chat_id,
        query_chat_type=query_chat_type,
        query_thread_id=query_thread_id,
        query_user_name=query_user_name,
    )
    return
```

### 2. Handler method + message injection

Added after `_handle_gmail_triage_callback`:

- `_handle_agentmail_callback()` — parses action/key, authorizes, looks up pending action, consumes key, dispatches
- `_inject_user_message()` — creates a `MessageEvent` with `SessionSource(platform=Platform.TELEGRAM)` and dispatches via `self.handle_message()`

## Reapply After Hermes Updates

After any `hermes update`, reapply this patch:

```bash
# The patch lives in the Hermes codebase, not this repo.
# To reapply, re-add the am: callback handler to:
# ~/.hermes/hermes-agent/plugins/platforms/telegram/adapter.py
#
# 1. Add the am: routing block in _handle_callback_query (before sc: handler)
# 2. Add _handle_agentmail_callback method (after _handle_gmail_triage_callback)
# 3. Add _inject_user_message method
# 4. Clear pyc cache: find ~/.hermes/hermes-agent/ -name "*.pyc" -path "*telegram*" -delete
# 5. Restart gateway: hermes gateway restart
```

## Tested

- Callback fires on button press ✅
- Key consumed (one-time-use enforced) ✅
- Synthetic MessageEvent dispatched to active session ✅
- Agent reads email thread via AgentMail MCP ✅
- Agent drafts and sends reply via AgentMail MCP ✅
- Full loop: press Reply → agent reads email → agent drafts reply → reply sent ✅