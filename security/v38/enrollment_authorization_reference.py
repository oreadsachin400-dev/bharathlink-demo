"""Fail-closed device-enrollment authorization reference; NOT wired to production.

A successful authorization must be issued by a trusted approver after external
cryptographic signature verification. This module does not itself verify ECDSA
signatures or persist/consume database receipts.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import FrozenSet

@dataclass(frozen=True)
class Enrollment:
    user_id: str
    candidate_device_id: str
    signing_key_hash: str
    x25519_key_hash: str
    approver_device_id: str
    nonce: str
    expires_at: datetime
    purpose: str = "bharathlink.device-enrollment.v1"

@dataclass(frozen=True)
class VerifiedApproval:
    """Only the trusted signature-verification boundary may construct this."""
    enrollment: Enrollment
    signature_verified: bool
    approver_trusted: bool
    approver_revoked: bool

def authorize(approval: VerifiedApproval, *, expected_user: str,
              expected_device: str, expected_signing_hash: str,
              expected_x25519_hash: str, now: datetime,
              consumed_nonces: FrozenSet[str]) -> bool:
    e = approval.enrollment
    if now.tzinfo is None or e.expires_at.tzinfo is None:
        return False
    if not all(isinstance(v, str) and v.strip() for v in (
        e.user_id, e.candidate_device_id, e.approver_device_id,
        e.signing_key_hash, e.x25519_key_hash, e.nonce)):
        return False
    return all((
        approval.signature_verified,
        approval.approver_trusted,
        not approval.approver_revoked,
        e.purpose == "bharathlink.device-enrollment.v1",
        bool(e.nonce),
        e.nonce not in consumed_nonces,
        e.user_id == expected_user,
        e.candidate_device_id == expected_device,
        e.signing_key_hash == expected_signing_hash,
        e.x25519_key_hash == expected_x25519_hash,
        e.approver_device_id != e.candidate_device_id,
        e.expires_at > now,
        e.expires_at <= now + __import__('datetime').timedelta(minutes=10),
    ))
