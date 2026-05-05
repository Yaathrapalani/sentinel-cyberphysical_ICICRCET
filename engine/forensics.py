"""engine/forensics.py — Forensic Timeline + SHA256 Integrity Logger.
Fixed: session-isolated log files prevent cross-run appending/duplication.
"""
from __future__ import annotations
import hashlib
import json
import os
import time
from datetime import datetime
from typing import Optional

LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")


def _ensure_logs() -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)


def _sha256(entry: dict) -> str:
    raw = json.dumps(entry, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# Session ID stamped once at import time — isolates per-run log files
_SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")


def _log_path(filename: str) -> str:
    """Return session-namespaced path, e.g. detection_logs_20260505_003412.json"""
    base, ext = os.path.splitext(filename)
    return os.path.join(LOGS_DIR, f"{base}_{_SESSION_ID}{ext}")


def _write_log(filename: str, entry: dict) -> None:
    _ensure_logs()
    path = _log_path(filename)
    records = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            records = []
    records.append(entry)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)


class ForensicTimeline:
    """Chronological event trace with timestamps and SHA256 per event."""

    def __init__(self):
        self.events: list = []

    def record(self, event_type: str, detail: str,
               node_id: Optional[str] = None,
               severity: str = "INFO",
               extra: Optional[dict] = None) -> dict:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        entry: dict = {
            "timestamp":  ts,
            "epoch":      round(time.time(), 3),
            "event_type": event_type,
            "detail":     detail,
            "node_id":    node_id or "SYSTEM",
            "severity":   severity,
        }
        if extra:
            entry.update(extra)
        entry["sha256"] = _sha256(entry)
        self.events.append(entry)
        return entry

    def get_timeline(self) -> list:
        return list(self.events)

    def display(self) -> str:
        lines = []
        for e in self.events:
            node_part = f" | node={e['node_id']}" if e["node_id"] != "SYSTEM" else ""
            lines.append(
                f"[{e['timestamp']}] [{e['severity']:8s}] "
                f"{e['event_type']:30s} | {e['detail']}{node_part}"
            )
        return "\n".join(lines)

    def flush_to_file(self) -> str:
        _ensure_logs()
        path = _log_path("forensic_timeline.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.events, f, indent=2, default=str)
        return path

    def clear(self) -> None:
        self.events.clear()


class IntegrityLogger:
    """SHA256-chained audit logger — each entry hash-links to previous."""

    def __init__(self):
        self._prev_hash = "0" * 64

    def log_detection(self, node_id: str, tick: int,
                      cyber: float, physical: float,
                      correlation: float, attack_type: str,
                      severity: str, system_state: str) -> dict:
        entry = {
            "log_type":         "DETECTION",
            "timestamp":        datetime.now().isoformat(),
            "tick":             tick,
            "node_id":          node_id,
            "anomaly_scores":   {"cyber": round(cyber, 4), "physical": round(physical, 4)},
            "correlation_value": round(correlation, 4),
            "attack_type":      attack_type,
            "severity":         severity,
            "action_taken":     "DETECTION_LOGGED",
            "system_state":     system_state,
            "prev_hash":        self._prev_hash,
        }
        entry["sha256"]   = _sha256(entry)
        self._prev_hash   = entry["sha256"]
        _write_log("detection_logs.json", entry)
        return entry

    def log_response(self, node_id: str, tick: int,
                     action: str, attack_type: str,
                     severity: str, system_state: str,
                     success: bool = True) -> dict:
        entry = {
            "log_type":         "RESPONSE",
            "timestamp":        datetime.now().isoformat(),
            "tick":             tick,
            "node_id":          node_id,
            "anomaly_scores":   {},
            "correlation_value": None,
            "attack_type":      attack_type,
            "severity":         severity,
            "action_taken":     action,
            "system_state":     system_state,
            "success":          success,
            "prev_hash":        self._prev_hash,
        }
        entry["sha256"]   = _sha256(entry)
        self._prev_hash   = entry["sha256"]
        _write_log("response_logs.json", entry)
        return entry
