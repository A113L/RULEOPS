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


def test_log_line_is_separated_from_live_progress_frame():
    from rule_ranker.progress import write_log_line

    stream = io.StringIO()
    pbar = ProgressBar(100, "CELF", "rule", stream=stream, heartbeat=False)
    pbar.set_postfix_str("round=1 | heap=886,686")
    write_log_line("[CELF] first round started", stream=stream)
    pbar.close()

    output = stream.getvalue()
    assert "heap=886,686\x1b[K\r\x1b[K\n[CELF] first round started\n" in output
    assert "heap=886,686[CELF]" not in output


def test_ranker_log_uses_progress_aware_line_writer(monkeypatch):
    import sys
    from rule_ranker.progress import ProgressBar
    from rule_ranker.ranker_postprocess import log

    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    pbar = ProgressBar(10, "CELF", "rule", stream=stream, heartbeat=False)
    pbar.set_postfix_str("round=1 | rescored=9985")
    log("round 1: exact-resolve complete")
    pbar.close()

    output = stream.getvalue()
    assert "rescored=9985\x1b[K\r\x1b[K\n" in output
    assert "round 1: exact-resolve complete\n" in output
    assert "rescored=9985[CELF]" not in output


def test_progress_can_reset_rate_window_without_resetting_total_elapsed(monkeypatch):
    import rule_ranker.progress as progress_module

    now = [10.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: now[0])
    stream = io.StringIO()
    pbar = ProgressBar(100, "CELF", "rule", stream=stream, heartbeat=False)
    pbar.update(10, refresh=False)
    now[0] = 20.0
    pbar.reset_rate_window(refresh=False)
    pbar.update(5, refresh=False)
    now[0] = 25.0

    line = pbar._build_line()
    assert "15/100" in line
    assert "00:15" in line  # end-to-end elapsed clock was not reset
    assert "ETA 01:25" in line
    assert "1.0 rule/s" in line  # rate counts only the five post-reset items
    pbar.close()


def test_rolling_rate_uses_exact_window_boundary_and_minimum_sample_time(monkeypatch):
    import rule_ranker.progress as progress_module

    now = [0.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: now[0])
    rate = progress_module.RollingRate(
        window_seconds=30.0, min_elapsed_seconds=10.0
    )

    now[0] = 1.0
    rate.set_count(100)
    assert rate.rate() is None  # suppress unstable rates during warm-up

    now[0] = 10.0
    assert rate.rate() == 10.0

    now[0] = 20.0
    rate.set_count(400)
    now[0] = 40.0
    assert rate.rate() == 10.0  # (400 - 100) / the exact 30-second window

    # Once increments stop, throughput decays to zero as the old work ages out.
    now[0] = 51.0
    assert rate.rate() == 0.0


def test_progress_bar_can_use_rolling_rate_for_rate_and_eta(monkeypatch):
    import rule_ranker.progress as progress_module

    now = [0.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: now[0])
    stream = io.StringIO()
    pbar = ProgressBar(1000, "CELF", "rule", stream=stream, heartbeat=False,
                       rate_window_seconds=30.0, rate_min_elapsed_seconds=10.0)
    now[0] = 1.0
    pbar.update(100, refresh=False)
    now[0] = 9.0
    assert "ETA --:--" in pbar._build_line()
    assert "-- rule/s" in pbar._build_line()

    now[0] = 10.0
    pbar.update(100, refresh=False)
    line = pbar._build_line()
    assert "20.0 rule/s" in line
    assert "ETA 00:40" in line

    # Reset the moving window without resetting total elapsed or progress.
    now[0] = 20.0
    pbar.reset_rate_window(refresh=False)
    now[0] = 21.0
    pbar.update(50, refresh=False)
    now[0] = 30.0
    line = pbar._build_line()
    assert "250/1,000" in line
    assert "00:30" in line
    assert "5.0 rule/s" in line

    # A genuinely idle window is reported as zero, not as the old average.
    now[0] = 61.0
    line = pbar._build_line()
    assert "0.0 rule/s" in line
    assert "ETA --:--" in line
    pbar.close()
