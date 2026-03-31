"""
Tests for JsonlFileSink.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from bh_audit_logger import AuditSink, JsonlFileSink

from .conftest import make_test_event


def _read_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_write_and_readback(tmp_path: Path) -> None:
    event = make_test_event()
    with JsonlFileSink(tmp_path / "audit.jsonl") as sink:
        sink.emit(event)
    lines = _read_lines(tmp_path / "audit.jsonl")
    assert len(lines) == 1
    assert lines[0]["event_id"] == event["event_id"]


def test_multiple_events_append(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with JsonlFileSink(path) as sink:
        for i in range(3):
            sink.emit(make_test_event(event_id=f"1234567{i}-1234-5678-1234-567812345678"))
    assert len(_read_lines(path)) == 3


def test_creates_parent_directories(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c" / "audit.jsonl"
    sink = JsonlFileSink(deep)
    sink.emit(make_test_event())
    sink.close()
    assert deep.exists()
    assert len(_read_lines(deep)) == 1


def test_compact_json_no_indent(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with JsonlFileSink(path) as sink:
        sink.emit(make_test_event())
    raw = path.read_text().strip()
    assert "\n" not in raw
    assert "  " not in raw


def test_unicode_handling(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    event = make_test_event()
    event["resource"] = {"type": "Nota clínica — résumé"}
    with JsonlFileSink(path) as sink:
        sink.emit(event)
    lines = _read_lines(path)
    assert lines[0]["resource"]["type"] == "Nota clínica — résumé"


def test_flush_on_write(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlFileSink(path, flush=True)
    sink.emit(make_test_event())
    assert len(_read_lines(path)) == 1
    sink.close()


def test_close_idempotent(tmp_path: Path) -> None:
    sink = JsonlFileSink(tmp_path / "audit.jsonl")
    sink.emit(make_test_event())
    sink.close()
    sink.close()  # should not raise


def test_reopen_after_close(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlFileSink(path)
    sink.emit(make_test_event())
    sink.close()
    sink.emit(make_test_event(event_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
    sink.close()
    assert len(_read_lines(path)) == 2


def test_thread_safety(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlFileSink(path)
    errors: list[Exception] = []

    def writer(tid: int) -> None:
        try:
            for i in range(100):
                eid = f"{tid:08x}-{i:04x}-5678-1234-567812345678"
                sink.emit(make_test_event(event_id=eid))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    sink.close()
    assert not errors
    assert len(_read_lines(path)) == 1000


def test_large_event(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    event = make_test_event(metadata={"big": "x" * 10_000})
    with JsonlFileSink(path) as sink:
        sink.emit(event)
    lines = _read_lines(path)
    assert len(lines[0]["metadata"]["big"]) == 10_000


def test_sink_protocol(tmp_path: Path) -> None:
    sink = JsonlFileSink(tmp_path / "audit.jsonl")
    assert isinstance(sink, AuditSink)
    sink.close()


def test_context_manager(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    with JsonlFileSink(path) as sink:
        sink.emit(make_test_event())
    assert path.exists()
    assert len(_read_lines(path)) == 1
