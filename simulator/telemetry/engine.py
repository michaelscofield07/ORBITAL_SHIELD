"""
ORBITAL_SHIELD - Telemetry Replay Engine

Provides sequential replay of CubeSat telemetry records from the consolidated dataset.
Supports configurable playback speeds, start/stop/pause/reset/step controls,
and is completely decoupled from any web framework (FastAPI/WebSockets).
"""

import asyncio
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import threading
import time
from typing import Any, Callable, Generator, List, Optional, Union
import pandas as pd

from .converter import TelemetryConverter, row_to_telemetry_event
from .models import TelemetryEvent


class ReplayState(str, Enum):
    STOPPED = "STOPPED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"


@dataclass
class ReplayStatus:
    state: ReplayState
    current_index: int
    total_records: int
    emitted_count: int
    speed_multiplier: float
    base_interval_sec: float
    effective_interval_sec: float
    loop: bool
    progress_pct: float


class TelemetryReplayEngine:
    """
    Core Replay Engine for ORBITAL_SHIELD telemetry.
    Reads dataset records sequentially and emits standardized TelemetryEvent objects.
    """

    def __init__(
        self,
        dataset_path: Optional[Union[str, Path]] = None,
        dataframe: Optional[pd.DataFrame] = None,
        satellite_id: str = "SAT-ORBITAL-01",
        speed_multiplier: float = 1.0,
        base_interval_sec: float = 1.0,
        loop: bool = False,
    ):
        """
        Initialize the Replay Engine.

        Parameters:
        - dataset_path: Path to consolidated_dataset_raw.csv. If None, defaults to standard location.
        - dataframe: Optional pre-loaded DataFrame (for testing or memory efficiency).
        - satellite_id: Simulator satellite ID for telemetry headers.
        - speed_multiplier: Replay speed factor (1.0 = 1x, 2.0 = 2x faster, etc.).
        - base_interval_sec: Base delay in seconds between sequential events before speed multiplier.
        - loop: If True, loops back to index 0 upon reaching the end of the dataset.
        """
        if dataframe is not None:
            self.df = dataframe.copy()
        else:
            if dataset_path is None:
                dataset_path = Path(__file__).resolve().parent.parent / "data" / "consolidated_dataset_raw.csv"
            self.dataset_path = Path(dataset_path)
            if not self.dataset_path.exists():
                raise FileNotFoundError(f"Dataset CSV not found at: {self.dataset_path}")
            self.df = pd.read_csv(self.dataset_path)

        self.total_records: int = len(self.df)
        self.satellite_id: str = satellite_id
        self.converter = TelemetryConverter(satellite_id=self.satellite_id)

        # Replay configuration & state
        self.speed_multiplier: float = max(0.01, float(speed_multiplier))
        self.base_interval_sec: float = max(0.001, float(base_interval_sec))
        self.loop: bool = loop

        self._state: ReplayState = ReplayState.STOPPED
        self._current_index: int = 0
        self._emitted_count: int = 0
        self._lock = threading.RLock()
        self._callbacks: List[Callable[[TelemetryEvent], Any]] = []

        # Background threading worker handles
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # --- Properties & Status ---

    @property
    def state(self) -> ReplayState:
        with self._lock:
            return self._state

    @property
    def current_index(self) -> int:
        with self._lock:
            return self._current_index

    @property
    def emitted_count(self) -> int:
        with self._lock:
            return self._emitted_count

    @property
    def effective_interval_sec(self) -> float:
        return self.base_interval_sec / self.speed_multiplier

    def get_status(self) -> ReplayStatus:
        """Returns the current snapshot status of the replay engine."""
        with self._lock:
            progress = (
                (self._current_index / self.total_records) * 100.0
                if self.total_records > 0
                else 0.0
            )
            return ReplayStatus(
                state=self._state,
                current_index=self._current_index,
                total_records=self.total_records,
                emitted_count=self._emitted_count,
                speed_multiplier=self.speed_multiplier,
                base_interval_sec=self.base_interval_sec,
                effective_interval_sec=self.effective_interval_sec,
                loop=self.loop,
                progress_pct=round(progress, 2),
            )

    # --- Configuration Setters ---

    def set_speed(self, multiplier: float) -> None:
        """Sets the replay speed multiplier (e.g. 2.0 = 2x, 0.5 = 0.5x)."""
        with self._lock:
            if multiplier <= 0:
                raise ValueError("Speed multiplier must be greater than 0.")
            self.speed_multiplier = float(multiplier)

    def set_base_interval(self, seconds: float) -> None:
        """Sets the base interval delay in seconds between events."""
        with self._lock:
            if seconds <= 0:
                raise ValueError("Base interval must be greater than 0.")
            self.base_interval_sec = float(seconds)

    def set_loop(self, loop: bool) -> None:
        """Enable or disable looping at the end of the dataset."""
        with self._lock:
            self.loop = bool(loop)

    def register_callback(self, callback: Callable[[TelemetryEvent], Any]) -> None:
        """Register a callback function to receive each emitted TelemetryEvent."""
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable[[TelemetryEvent], Any]) -> None:
        """Unregister an existing callback function."""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    # --- Replay Navigation & Controls ---

    def get_current_event(self) -> Optional[TelemetryEvent]:
        """
        Returns the TelemetryEvent corresponding to the current record index
        without advancing the replay pointer.
        """
        with self._lock:
            if self.total_records == 0:
                return None
            idx = self._current_index
            if idx >= self.total_records:
                idx = max(0, self.total_records - 1)
            row = self.df.iloc[idx]
            return self.converter.convert_row(row)

    def step(self) -> Optional[TelemetryEvent]:
        """
        Advances the replay by one record and returns the converted TelemetryEvent.
        Returns None if dataset reached the end and loop is False.
        """
        with self._lock:
            if self.total_records == 0:
                return None

            if self._current_index >= self.total_records:
                if self.loop:
                    self._current_index = 0
                else:
                    self._state = ReplayState.COMPLETED
                    return None

            # Fetch row and advance index
            row = self.df.iloc[self._current_index]
            event = self.converter.convert_row(row)

            self._current_index += 1
            self._emitted_count += 1

            if self._current_index >= self.total_records and not self.loop:
                self._state = ReplayState.COMPLETED

            # Notify callbacks
            for cb in list(self._callbacks):
                try:
                    cb(event)
                except Exception:
                    pass

            return event

    def start(self) -> None:
        """Starts or resumes the replay."""
        with self._lock:
            if self._state == ReplayState.COMPLETED:
                # If completed, start from beginning
                self._current_index = 0
            self._state = ReplayState.RUNNING

    def pause(self) -> None:
        """Pauses the replay without resetting current position."""
        with self._lock:
            if self._state == ReplayState.RUNNING:
                self._state = ReplayState.PAUSED

    def stop(self) -> None:
        """Stops the replay and resets the index position to 0."""
        with self._lock:
            self._stop_worker()
            self._state = ReplayState.STOPPED
            self._current_index = 0

    def reset(self) -> None:
        """Resets replay index and counters to initial state."""
        with self._lock:
            self._stop_worker()
            self._state = ReplayState.STOPPED
            self._current_index = 0
            self._emitted_count = 0

    def seek(self, target_index: int) -> int:
        """
        Seeks to a specific record index.
        Returns the clamped actual index set.
        """
        with self._lock:
            if target_index < 0:
                target_index = 0
            elif target_index >= self.total_records:
                target_index = max(0, self.total_records - 1)

            self._current_index = target_index
            if self._state == ReplayState.COMPLETED and self._current_index < self.total_records:
                self._state = ReplayState.PAUSED
            return self._current_index

    # --- Background Worker & Streaming ---

    def start_background(self) -> None:
        """Starts background worker thread to continuously emit events."""
        with self._lock:
            if self._worker_thread and self._worker_thread.is_alive():
                return
            self._stop_event.clear()
            self._state = ReplayState.RUNNING
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="TelemetryReplayWorker",
                daemon=True,
            )
            self._worker_thread.start()

    def stop_background(self) -> None:
        """Stops the background worker thread."""
        self._stop_worker()

    def _stop_worker(self) -> None:
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            if threading.current_thread() != self._worker_thread:
                self._worker_thread.join(timeout=1.0)
        self._worker_thread = None

    def _worker_loop(self) -> None:
        """Internal background loop running on a dedicated thread."""
        while not self._stop_event.is_set():
            with self._lock:
                current_st = self._state

            if current_st == ReplayState.RUNNING:
                event = self.step()
                if event is None:
                    # Dataset finished and not looping
                    break

            # Sleep for effective interval (divided in chunks for responsive stopping)
            sleep_duration = self.effective_interval_sec
            step_sleep = 0.05
            elapsed = 0.0
            while elapsed < sleep_duration and not self._stop_event.is_set():
                time.sleep(min(step_sleep, sleep_duration - elapsed))
                elapsed += step_sleep

    def iter_events(self, limit: Optional[int] = None) -> Generator[TelemetryEvent, None, None]:
        """
        Synchronous generator yielding TelemetryEvent objects.
        """
        count = 0
        while True:
            if limit is not None and count >= limit:
                break
            event = self.step()
            if event is None:
                break
            count += 1
            yield event

    async def stream_events(
        self,
        limit: Optional[int] = None,
        interval_sec: Optional[float] = None,
        auto_start: bool = True,
    ):
        """
        Asynchronous generator yielding TelemetryEvent at configured playback rate.
        Suitable for WebSocket or async event broadcasting.
        """
        if auto_start:
            with self._lock:
                if self._state in (ReplayState.STOPPED, ReplayState.COMPLETED):
                    self.start()

        count = 0
        while True:
            if limit is not None and count >= limit:
                break

            with self._lock:
                if self._state == ReplayState.PAUSED:
                    await asyncio.sleep(0.05)
                    continue
                if self._state in (ReplayState.STOPPED, ReplayState.COMPLETED):
                    break

            event = self.step()
            if event is None:
                break

            count += 1
            yield event
            
            sleep_duration = interval_sec if interval_sec is not None else self.effective_interval_sec
            await asyncio.sleep(sleep_duration)
