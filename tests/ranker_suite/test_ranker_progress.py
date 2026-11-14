import io

from rule_ranker.progress import ProgressBar


def test_progress_uses_single_carriage_returned_line_and_throttles_updates(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr("rule_ranker.progress.time.monotonic", lambda: 1.0)

    pbar = ProgressBar(
        total=100,
        desc="TEST",
        unit="item",
        stream=stream,
        min_interval=0.5,
        heartbeat=False,
    )
    pbar.update(1)
    pbar.update(1)
    pbar.set_postfix_str("phase=work")
    pbar.close()

    output = stream.getvalue()
    assert "TEST" in output
    assert "phase=work" in output
    assert "2.0%" in output
    assert "\r" in output
    # A progress update must not create a newline for every item update.
    assert output.count("\n") == 1


def test_progress_context_manager_finishes_on_actual_count(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr("rule_ranker.progress.time.monotonic", lambda: 10.0)

    with ProgressBar(4, "WORK", "unit", stream=stream, heartbeat=False) as pbar:
        pbar.update(3)

    output = stream.getvalue()
    assert "75.0%" in output
    assert "3/4" in output
    assert output.endswith("\n")


def test_narrow_terminal_keeps_celf_diagnostic_postfix(monkeypatch):
    class _TTYStream(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(
        "rule_ranker.progress.shutil.get_terminal_size",
        lambda _fallback: __import__("os").terminal_size((110, 20)),
    )
    stream = _TTYStream()
    pbar = ProgressBar(250000, "CELF", "rule", stream=stream, heartbeat=False)
    line = (
        "CELF [--------------] 0.0% 0/250000 | 13:18 | ETA --:-- | -- rule/s "
        "| round=1 | stage=exact-resolve:1/1 | selected=0/250000 "
        "| batch=128 | gpu_dispatches=12867 | rescored=1097921"
    )
    fitted = pbar._fit_line(line)
    assert len(fitted) <= 109
    assert "gpu_dispatches=12867" in fitted
    assert "rescored=1097921" in fitted
    pbar.close()
