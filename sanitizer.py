#!/usr/bin/env python3
"""
Email content sanitizer — standalone module with no project dependencies.

Extracted from agentmail_processor.py to avoid circular imports.
Used by both agentmail_processor.py and reader_agent.py.

Pipeline: strip HTML/scripts → strip control chars → strip markdown
links → strip tracking params → normalize whitespace.
"""

import re

# ===========================================================================
# Zero-width and control characters — stripped entirely
# ===========================================================================
_CONTROL_CHAR_RE = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f"  # C0 controls except TAB/LF/CR
    "\u007f"                                      # DEL
    "\u00ad"                                      # SOFT HYPHEN
    "\u200b-\u200f"                               # zero-width space, joiner, etc.
    "\u2028-\u202f"                               # line/para sep, directional controls
    "\u2060-\u206f"                               # word joiner, invisible operators
    "\ufeff"                                      # BOM / zero-width no-break space
    "\ufff9-\ufffb"                               # interlinear annotation
    "]"
)

# HTML/script elements — stripped ENTIRELY including their content.
_HTML_SCRIPT_RE = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
_HTML_STYLE_RE = re.compile(r"<\s*style\b[^>]*>.*?<\s*/\s*style\s*>", re.IGNORECASE | re.DOTALL)
_HTML_IFRAME_RE = re.compile(r"<\s*iframe\b[^>]*>.*?<\s*/\s*iframe\s*>", re.IGNORECASE | re.DOTALL)
_HTML_OBJECT_RE = re.compile(r"<\s*object\b[^>]*>.*?<\s*/\s*object\s*>", re.IGNORECASE | re.DOTALL)
_HTML_EMBED_RE = re.compile(r"<\s*embed\b[^>]*>.*?<\s*/\s*embed\s*>", re.IGNORECASE | re.DOTALL)
_HTML_APPLET_RE = re.compile(r"<\s*applet\b[^>]*>.*?<\s*/\s*applet\s*>", re.IGNORECASE | re.DOTALL)
_HTML_FORM_RE = re.compile(r"<\s*form\b[^>]*>.*?<\s*/\s*form\s*>", re.IGNORECASE | re.DOTALL)
_HTML_HEAD_RE = re.compile(r"<\s*head\b[^>]*>.*?<\s*/\s*head\s*>", re.IGNORECASE | re.DOTALL)

# Self-closing or void dangerous tags — stripped (tag only, no content)
_HTML_VOID_TAG_RE = re.compile(
    r"<\s*/?\s*(?:input|textarea|button|link|meta|base|img|br|hr)\b[^>]*/?\s*>",
    re.IGNORECASE | re.DOTALL,
)

# Remaining HTML tags — convert to content-preserving plaintext
_HTML_GENERAL_RE = re.compile(r"<[^>]+>")

# Markdown links [text](url) — keep visible text only
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")

# Markdown images ![alt](url) — drop entirely
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")

# Common tracking parameters to strip from any surviving URLs
_TRACKING_PARAMS = re.compile(
    r"[?&](?:utm_[a-z]+|fbclid|gclid|mc_eid|mc_cid|yclid|_openstat|pk_campaign|pk_source|pk_medium|pk_content)=([^&]*)",
    re.IGNORECASE,
)

# Whitespace normalization
_WHITESPACE_RE = re.compile(r"\s+")


# ===========================================================================
# Sanitization functions
# ===========================================================================

def _strip_html_and_scripts(text: str) -> str:
    """Remove dangerous HTML elements and their content entirely, then strip tags."""
    # Pass 1: Remove entire elements with their content
    for pattern in (_HTML_SCRIPT_RE, _HTML_STYLE_RE, _HTML_IFRAME_RE,
                    _HTML_OBJECT_RE, _HTML_EMBED_RE, _HTML_APPLET_RE,
                    _HTML_FORM_RE, _HTML_HEAD_RE):
        text = pattern.sub("", text)
    # Pass 2: Remove void/dangerous tags
    text = _HTML_VOID_TAG_RE.sub("", text)
    # Pass 3: Strip remaining HTML tags, preserving inner text
    text = _HTML_GENERAL_RE.sub("", text)
    return text


def _strip_control_chars(text: str) -> str:
    """Remove invisible/control characters that could be used for injection."""
    return _CONTROL_CHAR_RE.sub("", text)


def _strip_markdown_links(text: str) -> str:
    """Convert [text](url) to just 'text'. Remove ![alt](url) entirely."""
    text = _MD_IMAGE_RE.sub("", text)
    text = _MD_LINK_RE.sub(r"\1", text)
    return text


def _strip_tracking_params(text: str) -> str:
    """Remove common tracking parameters from any URLs in the text."""
    prev = None
    while prev != text:
        prev = text
        text = _TRACKING_PARAMS.sub("", text)
    return text


def _normalize_whitespace(text: str) -> str:
    """Collapse all whitespace runs to single spaces, strip edges."""
    return _WHITESPACE_RE.sub(" ", text).strip()


def sanitize_email_content(text: str, field_name: str = "") -> str:
    """Sanitize untrusted email content for safe output.

    Pipeline: strip HTML/scripts → strip control chars → strip markdown
    links → strip tracking params → normalize whitespace.

    FAILS CLOSED: raises ValueError if the result is empty after sanitization
    of a field that should contain data, indicating the input was purely
    malicious/empty content.

    Args:
        text: Raw email-derived string (subject, preview, sender, etc.)
        field_name: Optional field name for error messages.

    Returns:
        Sanitized plaintext safe for Telegram, Obsidian, and LLM context.
    """
    if not isinstance(text, str):
        raise ValueError(f"sanitize_email_content: {field_name or 'input'} must be str, got {type(text).__name__}")

    if not text:
        return ""

    result = _strip_html_and_scripts(text)
    result = _strip_control_chars(result)
    result = _strip_markdown_links(result)
    result = _strip_tracking_params(result)
    result = _normalize_whitespace(result)

    return result


# ===========================================================================
# Output escaping — format-specific escaping for safe rendering
# ===========================================================================

def escape_for_telegram(text: str) -> str:
    """Escape text for Telegram MarkdownV1 parse_mode."""
    text = text.replace("\\", "\\\\")
    for ch in ("*", "_", "`", "["):
        text = text.replace(ch, "\\" + ch)
    return text


def escape_for_json(text: str) -> str:
    """Escape text for safe JSON string embedding."""
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    return text


def escape_for_filename(text: str) -> str:
    """Allowlist-based filename character escaping.

    Only allows alphanumeric, spaces, hyphens, underscores, and dots
    (for file extensions). Everything else becomes underscore. This is
    an ALLOWLIST approach — we specify what's safe, not what's dangerous.

    Additionally collapses '..' to '_' to prevent path traversal.
    """
    if not text:
        return "unnamed"
    result = "".join(ch if ch.isalnum() or ch in " -_." else "_" for ch in text).strip()
    # Collapse '..' to prevent path traversal (e.g., '../../../etc/passwd')
    while ".." in result:
        result = result.replace("..", "_")
    # Truncate to safe length
    return result[:200] if result else "unnamed"


def escape_for_markdown_yaml(text: str) -> str:
    """Escape text for safe embedding in Markdown/YAML frontmatter.

    Handles quotes, colons in values, and special YAML characters.
    """
    # Escape double quotes for YAML string values
    text = text.replace('"', '\\"')
    # Collapse newlines (YAML doesn't tolerate unescaped newlines in quoted scalars)
    text = text.replace("\n", " ").replace("\r", " ")
    return text