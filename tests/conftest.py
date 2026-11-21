import os
import secrets
import tempfile
from pathlib import Path

_test_dir = tempfile.TemporaryDirectory(prefix="fastapi-security-tests-")
os.environ["DB_PATH"] = str(Path(_test_dir.name) / "test.sqlite3")
os.environ["JWT_SECRET"] = secrets.token_urlsafe(48)
