import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy import update


def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def rotate_refresh_token(db, session_model, old_token):
    '''
    This function performs an atomic conditional update.

    Note: The field names refresh_token_hash, revoked_at, and expires_at are illustrative.
    They must match the actual session model in a project.
    '''
    old_hash = hash_token(old_token)

    new_token = secrets.token_urlsafe(48)
    new_hash = hash_token(new_token)

    stmt = (
        update(session_model)
        .where(
            session_model.refresh_token_hash == old_hash,
            session_model.revoked_at.is_(None),
            session_model.expires_at > datetime.now(timezone.utc),
        )
        .values(refresh_token_hash = new_hash)
    )

    result = db.execute(stmt)

    if result.rowcount != 1:
        db.rollback()
        return None

    db.commit()

    return new_token
