#!/usr/bin/env python3
"""PolicyEngine — rule-based decision engine for AgentMail action authorization.

Loads policy_config.yaml and validates EmailIntent objects against trust-level
rules. Fail-closed: if the config is missing, everything is blocked.

Usage:
    engine = PolicyEngine()
    intent = EmailIntent(...)
    decision = engine.validate(intent)
    if decision.approved:
        proceed()
    elif decision.required_confirmation:
        escalate_to_telegram()
"""

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime, timezone

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from intent_schema import EmailIntent, VALID_ACTIONS, VALID_TRUST_LEVELS


# ---------------------------------------------------------------------------
# PolicyDecision — result of policy validation
# ---------------------------------------------------------------------------
@dataclass
class PolicyDecision:
    """Result of validating an EmailIntent against policy rules.

    Attributes:
        approved: Whether the intent is allowed to proceed.
        reason: Human-readable explanation of the decision.
        required_confirmation: Whether the action needs Telegram user confirmation.
        audit_log_entry: Structured audit record for the decision.
    """
    approved: bool
    reason: str
    required_confirmation: bool
    audit_log_entry: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# PolicyEngine — loads config, validates intents
# ---------------------------------------------------------------------------
class PolicyEngine:
    """Rule-based policy engine for email action authorization.

    Loads policy rules from policy_config.yaml on init. If the config file
    is missing or unreadable, the engine operates in fail-closed mode:
    ALL actions are blocked with reason "policy config unavailable".

    The engine validates EmailIntent objects against trust-level rules and
    returns a PolicyDecision indicating whether the action is approved,
    requires confirmation, or is blocked.
    """

    # Default path — lives next to agentmail_processor.py
    DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "policy_config.yaml"

    def __init__(self, config_path: str | Path | None = None):
        self._config_path = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        self._config: dict = {}
        self._fail_closed = False
        self._load_config()

    def _load_config(self):
        """Load policy_config.yaml. Fall back to fail-closed if missing."""
        if not self._config_path.exists():
            print(f"POLICY_ENGINE: config not found at {self._config_path}, "
                  f"operating in fail-closed mode (block everything)", file=__import__("sys").stderr)
            self._fail_closed = True
            self._config = {}
            return

        if _YAML_AVAILABLE:
            import yaml as _yaml
            try:
                raw = self._config_path.read_text(encoding="utf-8")
                self._config = _yaml.safe_load(raw) or {}
            except _yaml.YAMLError as e:
                print(f"POLICY_ENGINE: failed to parse YAML: {e}", file=__import__("sys").stderr)
                self._fail_closed = True
                self._config = {}
        else:
            try:
                raw = self._config_path.read_text(encoding="utf-8")
                self._config = json.loads(raw)
            except json.JSONDecodeError as e:
                print(f"POLICY_ENGINE: YAML package not available and config is not JSON: {e}",
                      file=__import__("sys").stderr)
                self._fail_closed = True
                self._config = {}

        # Validate config structure
        if "policy" not in self._config:
            print("POLICY_ENGINE: missing 'policy' key in config, using fail-closed mode",
                  file=__import__("sys").stderr)
            self._fail_closed = True

    def _get_default_action(self) -> str:
        """Get the default action from config. Defaults to 'block'."""
        return self._config.get("policy", {}).get("default_action", "block")

    def _get_rules(self, trust_level: str) -> dict:
        """Get policy rules for a given trust level. Empty dict if not found."""
        return self._config.get("policy", {}).get("rules", {}).get(trust_level, {})

    def _should_log(self) -> bool:
        """Whether to log all policy decisions."""
        return self._config.get("policy", {}).get("log_all_decisions", True)

    def _get_audit_path(self) -> Path:
        """Get the audit log file path from config."""
        raw = self._config.get("audit", {}).get(
            "audit_log_path",
            "~/.agentmail/audit/policy_decisions.jsonl",
        )
        return Path(raw).expanduser()

    def _get_audit_settings(self) -> dict:
        """Get audit retention settings."""
        audit = self._config.get("audit", {})
        return {
            "retention_days": audit.get("retention_days", 90),
            "max_entries": audit.get("max_entries", 10000),
        }

    def _write_audit(self, entry: dict):
        """Append an audit log entry as JSONL."""
        if not self._should_log():
            return

        audit_path = self._get_audit_path()
        audit_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"POLICY_ENGINE: failed to write audit log: {e}", file=__import__("sys").stderr)

        # Enforce max entries (trim oldest)
        settings = self._get_audit_settings()
        self._trim_audit(audit_path, settings["max_entries"])

    def _trim_audit(self, audit_path: Path, max_entries: int):
        """Trim audit log to max_entries, removing oldest first."""
        if not audit_path.exists():
            return

        try:
            lines = audit_path.read_text(encoding="utf-8").splitlines()
        except Exception:
            return

        if len(lines) <= max_entries:
            return

        # Keep only the most recent max_entries
        trimmed = lines[-max_entries:]
        try:
            audit_path.write_text("\n".join(trimmed) + "\n", encoding="utf-8")
        except Exception:
            pass  # Non-critical — don't fail the policy check

    def validate(self, intent: EmailIntent, trust_level: str | None = None) -> PolicyDecision:
        """Validate an EmailIntent against policy rules.

        Args:
            intent: The EmailIntent to validate.
            trust_level: Override trust level. If None, uses intent.sender_trust_level.

        Returns:
            PolicyDecision with approved, reason, required_confirmation, and audit_log_entry.
        """
        trust = trust_level or intent.sender_trust_level
        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Fail-closed: if config didn't load, block everything
        if self._fail_closed:
            decision = PolicyDecision(
                approved=False,
                reason="Policy config unavailable — fail-closed mode: all actions blocked",
                required_confirmation=False,
                audit_log_entry={
                    "timestamp": now_iso,
                    "timestamp_epoch": now_ts,
                    "action": intent.action,
                    "sender_trust_level": trust,
                    "risk_level": intent.risk_level,
                    "requires_external_send": intent.requires_external_send,
                    "decision": "blocked",
                    "reason": "fail-closed: policy config unavailable",
                },
            )
            self._write_audit(decision.audit_log_entry)
            return decision

        rules = self._get_rules(trust)
        default_action = self._get_default_action()

        # Rule 1: Suspicious senders → always block
        if trust == "suspicious":
            reason = rules.get("reason", "Suspicious sender — all actions blocked")
            entry = {
                "timestamp": now_iso,
                "timestamp_epoch": now_ts,
                "action": intent.action,
                "sender_trust_level": trust,
                "risk_level": intent.risk_level,
                "requires_external_send": intent.requires_external_send,
                "decision": "blocked",
                "reason": reason,
            }
            decision = PolicyDecision(
                approved=False,
                reason=reason,
                required_confirmation=False,
                audit_log_entry=entry,
            )
            self._write_audit(entry)
            return decision

        # Rule 2-4: Check allow/block lists for the trust level
        allowed = rules.get("allow", [])
        blocked = rules.get("block", [])
        require_confirmation = rules.get("require_confirmation", [])

        # If action is explicitly blocked, deny it
        if intent.action in blocked:
            reason = rules.get("reason", f"Action '{intent.action}' blocked for {trust} senders")
            entry = {
                "timestamp": now_iso,
                "timestamp_epoch": now_ts,
                "action": intent.action,
                "sender_trust_level": trust,
                "risk_level": intent.risk_level,
                "requires_external_send": intent.requires_external_send,
                "decision": "blocked",
                "reason": reason,
            }
            decision = PolicyDecision(
                approved=False,
                reason=reason,
                required_confirmation=False,
                audit_log_entry=entry,
            )
            self._write_audit(entry)
            return decision

        # If action is not in the allowed list, apply default
        if allowed and intent.action not in allowed:
            default_reason = f"Action '{intent.action}' not in allowed list for {trust} senders " \
                            f"(allowed: {', '.join(allowed)})"
            entry = {
                "timestamp": now_iso,
                "timestamp_epoch": now_ts,
                "action": intent.action,
                "sender_trust_level": trust,
                "risk_level": intent.risk_level,
                "requires_external_send": intent.requires_external_send,
                "decision": default_action,
                "reason": default_reason,
            }
            decision = PolicyDecision(
                approved=(default_action != "block"),
                reason=default_reason,
                required_confirmation=False,
                audit_log_entry=entry,
            )
            self._write_audit(entry)
            return decision

        # Action is allowed — check if confirmation is required
        needs_confirm = False
        confirm_reason = ""

        # High-risk actions always require confirmation if trust < known
        if intent.risk_level == "high" and trust in ("unknown",):
            needs_confirm = True
            confirm_reason = f"High risk action from {trust} sender requires confirmation"

        # Check per-trust-level confirmation requirements
        if "high_risk" in require_confirmation and intent.risk_level == "high":
            needs_confirm = True
            confirm_reason = confirm_reason or f"High risk action requires confirmation ({trust})"

        # External send actions require confirmation if trust < known
        if intent.requires_external_send and trust in ("unknown",):
            needs_confirm = True
            confirm_reason = confirm_reason or \
                f"External send from {trust} sender requires confirmation"

        # Allowlisted senders with high risk — flag for confirmation only
        if trust == "allowlisted" and intent.risk_level == "high":
            needs_confirm = True
            confirm_reason = f"High risk action from allowlisted sender — flagged for confirmation"

        entry = {
            "timestamp": now_iso,
            "timestamp_epoch": now_ts,
            "action": intent.action,
            "sender_trust_level": trust,
            "risk_level": intent.risk_level,
            "requires_external_send": intent.requires_external_send,
            "decision": "approved" if not needs_confirm else "approved_pending_confirmation",
            "reason": confirm_reason if needs_confirm else f"Action '{intent.action}' approved for {trust} sender",
            "confirmation_required": needs_confirm,
        }

        decision = PolicyDecision(
            approved=True,
            reason=confirm_reason if needs_confirm else f"Action '{intent.action}' approved for {trust} sender",
            required_confirmation=needs_confirm,
            audit_log_entry=entry,
        )
        self._write_audit(entry)
        return decision