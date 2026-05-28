#!/usr/bin/env python3
"""EmailIntent — structured intent schema for AgentMail policy decisions.

Defines the dataclass representing an LLM's interpretation of what action
should be taken on an email, validated and type-checked before it reaches
the policy engine.
"""

from dataclasses import dataclass, field, asdict
import time


# Valid action types
VALID_ACTIONS = frozenset({"reply", "save", "ignore", "trust", "block"})

# Valid risk levels
VALID_RISK_LEVELS = frozenset({"low", "medium", "high"})

# Valid trust levels
VALID_TRUST_LEVELS = frozenset({"allowlisted", "known", "unknown", "suspicious"})


@dataclass
class EmailIntent:
    """Structured representation of an intended action on an email.

    Created by parsing LLM output or classification heuristics, then
    validated by the policy engine before any action is taken.

    Fields:
        action: The intended action — one of "reply", "save", "ignore", "trust", "block".
        to: Recipient email address. Empty string for non-reply actions.
        subject: Sanitized email subject line.
        summary: LLM's one-line description of the intended action.
        risk_level: Risk assessment — "low", "medium", or "high".
        requires_external_send: True if the action sends an email (reply).
        sender_trust_level: Trust level of the sender — one of the four levels.
        raw_intent: Original LLM JSON output for audit trail.
        timestamp: Unix epoch when the intent was created.
    """

    action: str
    to: str
    subject: str
    summary: str
    risk_level: str
    requires_external_send: bool
    sender_trust_level: str
    raw_intent: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        """Validate fields after initialization."""
        self._validate()

    def _validate(self):
        """Validate all required fields. Raises ValueError on invalid data."""
        if self.action not in VALID_ACTIONS:
            raise ValueError(
                f"Invalid action '{self.action}'. Must be one of: {sorted(VALID_ACTIONS)}"
            )

        if self.risk_level not in VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{self.risk_level}'. Must be one of: {sorted(VALID_RISK_LEVELS)}"
            )

        if self.sender_trust_level not in VALID_TRUST_LEVELS:
            raise ValueError(
                f"Invalid sender_trust_level '{self.sender_trust_level}'. "
                f"Must be one of: {sorted(VALID_TRUST_LEVELS)}"
            )

        if self.action == "reply" and not self.to:
            raise ValueError(
                "Reply action requires a 'to' address — got empty string"
            )

        if self.requires_external_send and self.action != "reply":
            raise ValueError(
                f"requires_external_send=True is only valid for 'reply' action, "
                f"got '{self.action}'"
            )

        if not self.subject:
            raise ValueError("subject must be a non-empty string")

        if not self.summary:
            raise ValueError("summary must be a non-empty string")

    @classmethod
    def from_dict(cls, data: dict) -> "EmailIntent":
        """Create an EmailIntent from a dictionary, validating required fields.

        Args:
            data: Dictionary with keys matching EmailIntent fields.
                  Missing required fields raise ValueError.

        Returns:
            Validated EmailIntent instance.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        required_fields = [
            "action", "to", "subject", "summary",
            "risk_level", "requires_external_send", "sender_trust_level",
        ]

        missing = [f for f in required_fields if f not in data or data[f] is None]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        return cls(
            action=str(data["action"]),
            to=str(data.get("to", "")),
            subject=str(data["subject"]),
            summary=str(data["summary"]),
            risk_level=str(data["risk_level"]),
            requires_external_send=bool(data["requires_external_send"]),
            sender_trust_level=str(data["sender_trust_level"]),
            raw_intent=data.get("raw_intent", {}),
            timestamp=float(data.get("timestamp", time.time())),
        )

    def to_dict(self) -> dict:
        """Serialize to dictionary for logging/audit."""
        return asdict(self)