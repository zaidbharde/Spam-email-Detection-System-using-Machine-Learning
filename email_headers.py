"""Normalize email headers and extract lightweight spam signals."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import Message
from email.utils import parseaddr


@dataclass(frozen=True)
class HeaderSignals:
    """Signals derived from sender and reply metadata."""

    sender_domain: str
    reply_domain: str
    display_name_present: bool
    domains_match: bool


def _domain(value: str) -> str:
    address = parseaddr(value)[1].strip().lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def extract_signals(message: Message) -> HeaderSignals:
    """Extract comparable domains without exposing full email addresses."""
    sender = message.get("From", "")
    reply_to = message.get("Reply-To", sender)
    sender_domain = _domain(sender)
    reply_domain = _domain(reply_to)
    display_name, _ = parseaddr(sender)
    return HeaderSignals(
        sender_domain=sender_domain,
        reply_domain=reply_domain,
        display_name_present=bool(display_name.strip()),
        domains_match=bool(sender_domain and sender_domain == reply_domain),
    )


def suspicious_header_flags(signals: HeaderSignals) -> set[str]:
    """Return interpretable flags suitable for model features or audit logs."""
    flags: set[str] = set()
    if not signals.sender_domain:
        flags.add("missing_sender_domain")
    if signals.sender_domain and not signals.domains_match:
        flags.add("reply_domain_mismatch")
    if not signals.display_name_present:
        flags.add("missing_display_name")
    return flags
