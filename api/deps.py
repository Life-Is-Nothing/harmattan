"""Shared Flask-facing dependencies for API blueprints."""
from __future__ import annotations

from core import db
from core.auth import get_runtime_token, require_token
from core.config import REPORTS_DIR, VERSION
from core.jobs import manager as job_manager
from core.logging_setup import get_logger
from core.responses import api_response
from core.state import state

log = get_logger("harmattan.api")
