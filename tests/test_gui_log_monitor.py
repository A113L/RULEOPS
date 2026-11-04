from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app


def reset_stage_state():
    with app.LOCK:
        app.STATE.update({
            "status": "running",
            "stage": "Starting engine",
            "stage_detail": "Launching the engine process…",
            "stage_started_at": None,
            "progress": None,
            "progress_completed": None,
            "progress_total": None,
            "progress_rate": None,
            "progress_rules": None,
            "paused": False,
            "pause_requested": False,
        })


def test_startup_enabled_disabled_summary_does_not_claim_active_phase():
    assert app.detect_active_stage("STAGE 0 : enabled — CPU exact-match") is None
    assert app.detect_active_stage("STAGE 1 : enabled — single-rule GPU sweep") is None
    assert app.detect_active_stage("STAGE 3 : disabled — genetic algorithm") is None


def test_real_phase_section_headings_are_detected():
    assert app.detect_active_stage("│ STAGE 0 — TOKEN-STRIP RULE EXTRACTION") == "Stage 0 · Token Strip"
    assert app.detect_active_stage("│ STAGE S — SEED EXTRACTION") == "Stage S · Built-in Seeds"
    assert app.detect_active_stage("│ STAGE 1 — SINGLE RULE SEARCH") == "Stage 1 · Single-rule GPU sweep"
    assert app.detect_active_stage("│ STAGE 2 — RULE CHAIN SEARCH") == "Stage 2 · Rule-chain search"
    assert app.detect_active_stage("│ STAGE 3 — GENETIC ALGORITHM RULE EVOLUTION") == "Stage 3 · Genetic Algorithm"


def test_live_subphase_markers_are_detected():
    assert app.detect_active_stage("[GPU] Building bloom filter on GPU …") == "GPU Setup · Bloom Filter"
    assert app.detect_active_stage("[CELF] GPU recompute | recovered=2,000") == "Rule Selection · CELF"
    assert app.detect_active_stage("POST-PROCESSING — Signature-Based Functional Minimization") == "Minimization"
    assert app.detect_active_stage("[MINIMIZE] Candidates : 20,000") == "Minimization"
    assert app.detect_active_stage("[S3] pop=200 max_gen=50 elite=15%") == "Stage 3 · Genetic Algorithm"


def test_minimization_done_message_is_not_misread_as_run_completion():
    assert app.detect_active_stage("[MINIMIZE] Done") == "Minimization"
    assert app.detect_active_stage("DONE  rulest finished in 32.1s") == "Completed"


def test_progress_percent_updates_active_phase_and_detail():
    reset_stage_state()
    line = "  STAGE 2:  42%|██████████ | 42/100 [00:10<00:12, 4.2 batch/s]"
    app.update_stage(line)
    assert app.STATE["stage"] == "Stage 2 · Rule-chain search"
    assert app.STATE["progress"] == 42
    assert "42%" in app.STATE["stage_detail"]
    assert app.STATE["stage_started_at"] is not None


def test_celf_selection_heartbeat_updates_the_live_phase_detail():
    reset_stage_state()
    line = (
        "\x1b[96m[CELF] Greedy selection | selected=5/50 (10.0%) "
        "| recovered=2,000/12,000 (16.7%) | heap=40,000 "
        "| exact_scans=12 | elapsed=32s\x1b[0m"
    )
    app.update_stage(line)
    assert app.STATE["stage"] == "Rule Selection · CELF"
    assert app.STATE["stage_detail"].startswith("[CELF] Greedy selection")
    assert "selected=5/50" in app.STATE["stage_detail"]


def test_progress_count_can_be_used_when_percent_is_absent():
    reset_stage_state()
    app.update_stage("[CELF] GPU recompute | 25/100 [00:20<01:00]")
    assert app.STATE["stage"] == "Rule Selection · CELF"
    assert app.STATE["progress"] == 25


def test_terminal_cleaner_preserves_full_long_line_and_removes_ansi():
    long_text = "Important counter: " + ("1234567890" * 80)
    raw = "\x1b[96m" + long_text + "\x1b[0m\x1b[K"
    assert app.clean_terminal_text(raw) == long_text


def test_gui_has_wrap_expand_and_live_phase_detail_controls():
    web = Path(app.__file__).resolve().parent / "web"
    html = (web / "index.html").read_text(encoding="utf-8")
    js = (web / "app.js").read_text(encoding="utf-8")
    css = (web / "styles.css").read_text(encoding="utf-8")
    assert 'id="current-stage-detail"' in html
    assert 'id="wrap-log"' in html
    assert 'id="expand-log"' in html
    assert 'id="terminal-window"' in html
    assert "current-stage-detail" in js
    assert "terminal-window').classList.toggle('expanded')" in js
    assert ".log-message" in css and ".terminal-window.expanded" in css


def test_celf_upper_bound_bar_updates_phase_progress_from_web_log():
    reset_stage_state()
    line = (
        "[CELF] Upper-bound pass | [██████████··············] 42% | "
        "scanned=420,000/1,000,000 | speed=12,500.00 rules/s | avg=11,800.00 rules/s"
    )
    app.update_stage(line)
    assert app.STATE["stage"] == "Rule Selection · CELF"
    assert app.STATE["progress"] == 42
    assert app.STATE["stage_detail"].startswith("[CELF] Upper-bound pass")


def test_windows_stage_zero_progress_parses_count_and_word_rate():
    reset_stage_state()
    line = (
        "[19:54:38] STAGE 0 :  23%|████████████████████████████▌                         "
        "| 234375/999997 [00:19<00:16] , rules=2293, spd=12.0K words/s"
    )
    app.update_stage("\x1b[96m" + line + "\x1b[0m\x1b[K")
    assert app.STATE["stage"] == "Stage 0 · Token Strip"
    assert app.STATE["progress"] == 23
    assert app.STATE["progress_completed"] == 234375
    assert app.STATE["progress_total"] == 999997
    assert app.STATE["progress_rate"] == "12.0K words/s"
    assert app.STATE["progress_rules"] == 2293


def test_windows_stage_one_progress_parses_combo_rate():
    reset_stage_state()
    line = (
        "[19:55:05] STAGE 1 :  11%|█████████████                         "
        "| 1,602,667/14,343,719 [00:12<01:36] , rules=1939, spd=791.5M combos/s"
    )
    app.update_stage(line)
    assert app.STATE["stage"] == "Stage 1 · Single-rule GPU sweep"
    assert app.STATE["progress"] == 11
    assert app.STATE["progress_completed"] == 1602667
    assert app.STATE["progress_total"] == 14343719
    assert app.STATE["progress_rate"] == "791.5M combos/s"
    assert app.STATE["progress_rules"] == 1939


def test_progress_counts_reset_when_stage_changes():
    reset_stage_state()
    app.update_stage("STAGE 0 : 100%|████| 999997/999997 [00:28<00:00] , spd=35.6K words/s")
    app.update_stage("│ STAGE 1 — SINGLE RULE SEARCH")
    assert app.STATE["stage"] == "Stage 1 · Single-rule GPU sweep"
    assert app.STATE["progress"] is None
    assert app.STATE["progress_completed"] is None
    assert app.STATE["progress_total"] is None
    assert app.STATE["progress_rate"] is None
    assert app.STATE["progress_rules"] is None
