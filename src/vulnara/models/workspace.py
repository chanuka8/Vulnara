import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def generate_uuid() -> str:
    return str(uuid.uuid4())


def current_utc_time() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Project:
    """Represents a security assessment project or client workspace."""
    name: str
    description: str = ""
    id: str = field(default_factory=generate_uuid)
    created_at: str = field(default_factory=current_utc_time)


@dataclass
class ScanRecord:
    """Represents a single scan execution within a project."""
    project_id: str
    target_url: str
    profile_name: str
    status: str = "pending"  # pending, running, completed, failed
    id: str = field(default_factory=generate_uuid)
    started_at: str = field(default_factory=current_utc_time)
    completed_at: Optional[str] = None
    error_message: Optional[str] = None