import sqlite3
from pathlib import Path
from typing import List, Optional

from vulnara.models.workspace import Project, ScanRecord


class DatabaseManager:
    """Handles SQLite database operations for workspaces and scan history."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._initialize_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Establish and return a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_schema(self) -> None:
        """Create tables if they do not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    profile_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_message TEXT,
                    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
                )
            """)
            
            conn.commit()

    def create_project(self, name: str, description: str = "") -> Project:
        """Create a new project workspace."""
        project = Project(name=name, description=description)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO projects (id, name, description, created_at) VALUES (?, ?, ?, ?)",
                    (project.id, project.name, project.description, project.created_at)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                raise ValueError(f"Project with name '{name}' already exists.")
                
        return project

    def get_project_by_name(self, name: str) -> Optional[Project]:
        """Retrieve a project by its name."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, description, created_at FROM projects WHERE name = ?", (name,))
            row = cursor.fetchone()
            
            if row:
                return Project(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    created_at=row["created_at"]
                )
        return None

    def create_scan_record(self, project_id: str, target_url: str, profile_name: str) -> ScanRecord:
        """Initialize a new scan record linked to a project."""
        record = ScanRecord(project_id=project_id, target_url=target_url, profile_name=profile_name)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (id, project_id, target_url, profile_name, status, started_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (record.id, record.project_id, record.target_url, record.profile_name, record.status, record.started_at)
            )
            conn.commit()
            
        return record

    def update_scan_status(self, scan_id: str, status: str, completed_at: Optional[str] = None, error_message: Optional[str] = None) -> None:
        """Update the status of an existing scan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scans 
                SET status = ?, completed_at = ?, error_message = ?
                WHERE id = ?
                """,
                (status, completed_at, error_message, scan_id)
            )
            conn.commit()