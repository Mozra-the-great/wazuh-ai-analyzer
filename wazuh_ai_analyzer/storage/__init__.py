"""SQLite storage: connections, versioned additive migrations, repository.

The database schema is a public read interface for external tools; see
`contract` for everything that is frozen.
"""

from .db import Database
from .repo import BatchRecord, FindingRecord, NewFinding, Repository
from .schema import LATEST_VERSION, MigrationResult, migrate

__all__ = [
    "LATEST_VERSION",
    "BatchRecord",
    "Database",
    "FindingRecord",
    "MigrationResult",
    "NewFinding",
    "Repository",
    "migrate",
]
