"""Alert ingestion: live tail, backlog, watermark, sanitising (#84).

Modules:

* `lines`     bounded line reading (`ALERT_LINE_MAX`, R3)
* `parse`     strict JSON parsing and the `MIN_LEVEL` filter
* `sanitize`  the only gate from raw alert fields to the analysis (`group_alerts`)
* `archives`  file identity, first-line digests, Wazuh's dated archives
* `watermark` `watermark.json` v2, shared with the legacy analyzer
* `planner`   startup reconciliation of the watermark with the disk
* `batches`   storing batches, the live flush window
* `live`      the live tailer
* `backlog`   the throttled backlog worker
* `service`   `Ingest`, the wiring used by the pipeline
"""

from .batches import StoredBatch
from .counters import IngestStats
from .service import Ingest

__all__ = ["Ingest", "IngestStats", "StoredBatch"]
