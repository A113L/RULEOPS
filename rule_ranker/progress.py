"""Unified, low-noise terminal progress renderer used by all ranker stages."""

from __future__ import annotations

import math
import os
import shutil
import sys
import threading
import time
import weakref
from collections import deque
from typing import Optional, TextIO


_ACTIVE_PROGRESS_BARS = weakref.WeakSet()
_ACTIVE_PROGRESS_BARS_LOCK = threading.RLock()


def write_log_line(message: object, *, stream: Optional[TextIO] = None) -> None:
    """Write a durable log line without joining it to an active progress row.

    ProgressBar intentionally keeps its current frame open with a carriage
    return. A plain ``print()`` therefore appends log text to that frame in
    captured/non-TTY output. Close and clear the frame before writing, then
    redraw it so the progress indicator remains live.
    """
    target = stream or sys.stdout
    text = str(message).rstrip("\r\n")
    with _ACTIVE_PROGRESS_BARS_LOCK:
        bars = [
            bar for bar in _ACTIVE_PROGRESS_BARS
            if bar.stream is target and not bar.closed
        ]
    if not bars:
        target.write(text + "\n")
        target.flush()
        return

    # There should normally be one ranker progress bar per stream. If nested
    # stages happen to share a stream, redraw the most recently created one.
    bar = max(bars, key=lambda item: item.start_time)
    with bar._lock:
        if bar.closed:
            target.write(text + "\n")
            target.flush()
            return
        # Terminate the in-place progress frame, clear its visual contents,
        # and emit the log on a dedicated line. This works for both TTY and
        # redirected stdout (where carriage returns are otherwise preserved).
        bar._write("\r\x1b[K\n")
        bar._write(text + "\n")
        bar.refresh(force=True)


class RollingRate:
    """Track a cumulative counter over a bounded, moving time window.

    ``rate()`` returns ``None`` until ``min_elapsed_seconds`` of observations
    are available. The sample immediately before the window boundary is kept
    as the baseline, so sparse updates do not create artificially short windows.
    """

    def __init__(
        self,
        window_seconds: float = 30.0,
        min_elapsed_seconds: float = 10.0,
        *,
        initial_count: int = 0,
    ) -> None:
        self.window_seconds = max(0.1, float(window_seconds))
        self.min_elapsed_seconds = min(
            self.window_seconds, max(0.0, float(min_elapsed_seconds))
        )
        self._lock = threading.RLock()
        self.reset(initial_count=initial_count)

    def reset(self, *, initial_count: int = 0, now: Optional[float] = None) -> None:
        timestamp = time.monotonic() if now is None else float(now)
        with self._lock:
            self.start_time = timestamp
            self.current_count = max(0, int(initial_count))
            self._samples = deque([(timestamp, self.current_count)])

    def set_count(self, count: int, *, now: Optional[float] = None) -> None:
        timestamp = time.monotonic() if now is None else float(now)
        with self._lock:
            value = max(self.current_count, int(count))
            if value == self.current_count:
                return
            self.current_count = value
            self._samples.append((timestamp, value))

    def rate(self, *, now: Optional[float] = None) -> Optional[float]:
        timestamp = time.monotonic() if now is None else float(now)
        with self._lock:
            elapsed = max(0.0, timestamp - self.start_time)
            if elapsed < self.min_elapsed_seconds:
                return None

            cutoff = max(self.start_time, timestamp - self.window_seconds)
            # Keep the newest sample at or before cutoff as the rate baseline.
            while len(self._samples) > 1 and self._samples[1][0] <= cutoff:
                self._samples.popleft()

            _baseline_time, baseline_count = self._samples[0]
            sample_elapsed = timestamp - cutoff
            if sample_elapsed < self.min_elapsed_seconds or sample_elapsed <= 0.0:
                return None
            # The cumulative counter is piecewise constant between observations.
            # Use its value at the exact left edge of the window, not the timestamp
            # of the older observation that supplied that value.
            return max(0, self.current_count - baseline_count) / sample_elapsed


class ProgressBar:
    """Single-line progress bar with throttled, in-place terminal updates.

    The renderer deliberately avoids tqdm so every stage of the application uses
    the same compact format and refresh policy. Updates are throttled to avoid
    terminal flooding even when the caller processes items one-by-one.
    """

    def __init__(
        self,
        total: int,
        desc: str,
        unit: str = "it",
        *,
        stream: Optional[TextIO] = None,
        min_interval: float = 0.5,
        bar_width: int = 24,
        enabled: bool = True,
        heartbeat: bool = True,
        rate_window_seconds: Optional[float] = None,
        rate_min_elapsed_seconds: float = 10.0,
    ) -> None:
        self.stream = stream or sys.stdout
        self.total = max(1, int(total))
        self.desc = str(desc)
        self.unit = str(unit).strip() or "it"
        self.min_interval = max(0.1, float(min_interval))
        self.bar_width = max(10, int(bar_width))
        self.enabled = bool(enabled)
        self.n = 0
        self.postfix = ""
        self.start_time = time.monotonic()
        # Total elapsed time remains anchored to start_time. The rate window
        # can be reset at phase boundaries (CELF's first winner) without
        # falsifying the displayed end-to-end elapsed duration.
        self.rate_start_time = self.start_time
        self.rate_start_n = 0
        self.rate_tracker = (
            RollingRate(
                rate_window_seconds,
                rate_min_elapsed_seconds,
                initial_count=self.n,
            )
            if rate_window_seconds is not None else None
        )
        self.last_render = 0.0
        self.closed = False
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._terminal_width = 0
        self._thread = None

        if self.enabled:
            with _ACTIVE_PROGRESS_BARS_LOCK:
                _ACTIVE_PROGRESS_BARS.add(self)
            self.refresh(force=True)
            if heartbeat:
                self._thread = threading.Thread(
                    target=self._heartbeat_loop,
                    name="ranker-progress-heartbeat",
                    daemon=True,
                )
                self._thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.min_interval):
            self.refresh()

    @staticmethod
    def _format_duration(seconds: float) -> str:
        if not math.isfinite(seconds) or seconds < 0:
            return "--:--"
        total = int(seconds)
        hours, rem = divmod(total, 3600)
        minutes, secs = divmod(rem, 60)
        if hours:
            return f"{hours:d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    def _write(self, text: str) -> None:
        try:
            data = text.encode("utf-8", errors="replace")
            fileno = self.stream.fileno()
            os.write(fileno, data)
        except (AttributeError, OSError, ValueError):
            self.stream.write(text)
            self.stream.flush()

    def _build_line(self) -> str:
        now = time.monotonic()
        elapsed = max(0.0, now - self.start_time)
        rate_elapsed = max(0.0, now - self.rate_start_time)
        rate_items = max(0, self.n - self.rate_start_n)
        rate_available = True
        if self.rate_tracker is None:
            rate = rate_items / rate_elapsed if rate_elapsed > 0 else 0.0
            rate_available = rate > 0.0
        else:
            self.rate_tracker.set_count(self.n, now=now)
            measured_rate = self.rate_tracker.rate(now=now)
            rate_available = measured_rate is not None
            rate = measured_rate if measured_rate is not None else 0.0
        fraction = min(1.0, max(0.0, self.n / self.total))
        filled = int(round(self.bar_width * fraction))
        filled = min(self.bar_width, max(0, filled))
        bar = "#" * filled + "-" * (self.bar_width - filled)
        remaining = max(0, self.total - self.n)
        eta = remaining / rate if rate > 0 else float("nan")
        rate_text = (
            f"{rate:,.1f} {self.unit}/s"
            if rate_available else f"-- {self.unit}/s"
        )
        postfix = f" | {self.postfix}" if self.postfix else ""
        return (
            f"{self.desc} [{bar}] {fraction * 100:5.1f}% "
            f"{self.n:,}/{self.total:,} | {self._format_duration(elapsed)} "
            f"| ETA {self._format_duration(eta)} | {rate_text}{postfix}"
        )

    def _fit_line(self, line: str) -> str:
        try:
            width = shutil.get_terminal_size((120, 20)).columns
        except (OSError, ValueError):
            width = 120
        max_chars = max(1, width - 1)
        if width <= 20 or len(line) <= max_chars:
            return line

        # CELF progress carries durable diagnostic fields in its postfix.
        # When the terminal is narrow, shorten the visual prefix first and
        # keep the complete postfix (especially gpu_dispatches/rescored).
        marker = " | round="
        marker_at = line.find(marker)
        if marker_at >= 0:
            prefix = line[:marker_at]
            suffix = line[marker_at + len(marker):].replace(" | ", " ")
            if len(suffix) > max_chars - 24:
                tokens = suffix.split()
                # Preserve stage/round context and the final counters.
                if len(tokens) > 6:
                    suffix = " ".join(tokens[:3] + tokens[-3:])
            prefix_budget = max_chars - len(suffix) - 3
            if prefix_budget >= 12:
                return prefix[:prefix_budget] + "..." + suffix

        # Generic progress lines have no structured postfix. Preserve both
        # their leading phase/progress and trailing diagnostic context.
        head = max(12, (max_chars - 3) // 2)
        tail = max_chars - head - 3
        return line[:head] + "..." + (line[-tail:] if tail > 0 else "")

    def refresh(self, *, force: bool = False) -> None:
        if not self.enabled:
            return
        with self._lock:
            if self.closed:
                return
            now = time.monotonic()
            if not force and (now - self.last_render) < self.min_interval:
                return
            line = self._fit_line(self._build_line())
            self.last_render = now
            # Always use one carriage-returned frame while the process is alive.
            # This avoids the newline flood caused by repeated progress writes.
            self._write("\r" + line + "\x1b[K")

    def update(self, value: int = 1, *, refresh: bool = True) -> None:
        with self._lock:
            if self.closed:
                return
            self.n += max(0, int(value))
            if self.rate_tracker is not None:
                self.rate_tracker.set_count(self.n)
        if refresh:
            self.refresh()

    def set_total(self, total: int, *, refresh: bool = True) -> None:
        with self._lock:
            if self.closed:
                return
            self.total = max(1, int(total), self.n)
        if refresh:
            self.refresh(force=True)

    def reset_rate_window(self, *, refresh: bool = True) -> None:
        """Start a new throughput/ETA window without resetting progress.

        The overall elapsed clock and current progress count are preserved.
        This is useful when an initial setup phase should not dilute the rate
        of the steady-state work that follows it.
        """
        with self._lock:
            if self.closed:
                return
            self.rate_start_time = time.monotonic()
            self.rate_start_n = self.n
            if self.rate_tracker is not None:
                self.rate_tracker.reset(initial_count=self.n, now=self.rate_start_time)
        if refresh:
            self.refresh(force=True)

    def set_postfix_str(self, text: str, *, refresh: bool = True) -> None:
        with self._lock:
            if self.closed:
                return
            self.postfix = str(text)
        if refresh:
            self.refresh(force=True)

    def set_postfix(self, values, *, refresh: bool = True) -> None:
        if isinstance(values, dict):
            text = " | ".join(f"{k}={v}" for k, v in values.items())
        else:
            text = str(values)
        self.set_postfix_str(text, refresh=refresh)

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            if self.closed:
                return
            self.closed = True
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=max(0.5, self.min_interval * 2))
        with self._lock:
            # Do not fake completion. The final frame reflects the actual count.
            self._write("\r" + self._fit_line(self._build_line()) + "\x1b[K\n")
        with _ACTIVE_PROGRESS_BARS_LOCK:
            _ACTIVE_PROGRESS_BARS.discard(self)
