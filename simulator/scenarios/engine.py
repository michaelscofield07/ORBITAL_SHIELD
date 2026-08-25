"""
ORBITAL_SHIELD - Scenario Engine

Manages the execution of controlled simulation scenarios (NORMAL, TELEMETRY_ANOMALY,
MESSAGE_BURST, MESSAGE_REPLAY). Fully decoupled from dataset storage and replay engine.
"""

from collections import deque
from datetime import datetime, timezone
import random
import threading
from typing import Any, Dict, Generator, Iterable, List, Optional, Union
import uuid

from simulator.telemetry.models import TelemetryData, TelemetryEvent
from .models import (
    BaseScenarioConfig,
    MessageBurstConfig,
    MessageReplayConfig,
    NormalScenarioConfig,
    ScenarioStatus,
    ScenarioType,
    TelemetryAnomalyConfig,
)


class ScenarioEngine:
    """
    Scenario Engine for transforming telemetry event streams under controlled scenarios.
    Default state is always NORMAL (unaltered pass-through).
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._active_scenario: ScenarioType = ScenarioType.NORMAL
        self._config: BaseScenarioConfig = NormalScenarioConfig()
        self._frames_processed: int = 0
        self._frames_modified: int = 0
        self._scenario_frame_count: int = 0

        # Replay buffer for MESSAGE_REPLAY scenario
        self._replay_buffer: deque = deque()
        self._replay_cycle_count: int = 0
        self._replay_index: int = 0

        # Deterministic random generator
        self._rng = random.Random()

    @property
    def active_scenario(self) -> ScenarioType:
        with self._lock:
            return self._active_scenario

    def get_status(self) -> ScenarioStatus:
        """Returns the current status snapshot of the scenario engine."""
        with self._lock:
            return ScenarioStatus(
                active_scenario=self._active_scenario,
                is_active=(self._active_scenario != ScenarioType.NORMAL),
                frames_processed=self._frames_processed,
                frames_modified=self._frames_modified,
                config=self._config.model_dump(),
            )

    def set_scenario(
        self,
        scenario_type: Union[ScenarioType, str],
        config: Optional[BaseScenarioConfig] = None,
    ) -> None:
        """
        Explicitly activate a scenario with optional configuration.
        """
        with self._lock:
            if isinstance(scenario_type, str):
                scenario_type = ScenarioType(scenario_type)

            self._active_scenario = scenario_type
            self._scenario_frame_count = 0

            if config is not None:
                self._config = config
            else:
                if scenario_type == ScenarioType.NORMAL:
                    self._config = NormalScenarioConfig()
                elif scenario_type == ScenarioType.TELEMETRY_ANOMALY:
                    self._config = TelemetryAnomalyConfig()
                elif scenario_type == ScenarioType.MESSAGE_BURST:
                    self._config = MessageBurstConfig()
                elif scenario_type == ScenarioType.MESSAGE_REPLAY:
                    self._config = MessageReplayConfig()

            # Initialize seed for deterministic behavior
            if self._config.seed is not None:
                self._rng = random.Random(self._config.seed)
            else:
                self._rng = random.Random()

            # Reset replay state
            self._replay_buffer.clear()
            self._replay_cycle_count = 0
            self._replay_index = 0

    def reset_to_normal(self) -> None:
        """Resets scenario engine back to default NORMAL operational state."""
        self.set_scenario(ScenarioType.NORMAL)

    def process_event(self, event: TelemetryEvent) -> List[TelemetryEvent]:
        """
        Processes an incoming TelemetryEvent through the active scenario pipeline.
        Returns a list of TelemetryEvent objects (usually 1, or multiple for bursts).
        """
        with self._lock:
            self._frames_processed += 1
            self._scenario_frame_count += 1

            # Check if duration limit reached
            if (
                self._config.duration_frames is not None
                and self._scenario_frame_count > self._config.duration_frames
                and self._active_scenario != ScenarioType.NORMAL
            ):
                self.reset_to_normal()

            if self._active_scenario == ScenarioType.NORMAL:
                return self._handle_normal(event)
            elif self._active_scenario == ScenarioType.TELEMETRY_ANOMALY:
                return self._handle_telemetry_anomaly(event, self._config)  # type: ignore
            elif self._active_scenario == ScenarioType.MESSAGE_BURST:
                return self._handle_message_burst(event, self._config)  # type: ignore
            elif self._active_scenario == ScenarioType.MESSAGE_REPLAY:
                return self._handle_message_replay(event, self._config)  # type: ignore
            else:
                return self._handle_normal(event)

    def _handle_normal(self, event: TelemetryEvent) -> List[TelemetryEvent]:
        """Pass-through unaltered event."""
        return [event]

    def _handle_telemetry_anomaly(
        self, event: TelemetryEvent, config: TelemetryAnomalyConfig
    ) -> List[TelemetryEvent]:
        """
        Injects controlled telemetry perturbations (elevated memory, page faults, error counters).
        """
        self._frames_modified += 1
        data_dict = event.data.model_dump()

        # Apply synthetic perturbations
        data_dict["MemoryAnonMB"] = round(data_dict["MemoryAnonMB"] * config.memory_multiplier, 6)
        data_dict["MemoryFileMB"] = round(data_dict["MemoryFileMB"] * config.memory_multiplier, 6)
        data_dict["MemoryPageFaults"] = int(config.inject_page_faults)
        data_dict["CommandErrorCounter"] = int(config.corrupt_command_errors)

        # Optional jitter from deterministic RNG
        jitter = self._rng.uniform(0.01, 0.05)
        data_dict["SlidingWindowMaxIntervalSec"] = round(data_dict["SlidingWindowMaxIntervalSec"] + jitter, 6)

        anomalous_data = TelemetryData(**data_dict)
        anomalous_event = TelemetryEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            source=event.source,
            satellite_id=event.satellite_id,
            event_type=event.event_type,
            data=anomalous_data,
        )
        return [anomalous_event]

    def _handle_message_burst(
        self, event: TelemetryEvent, config: MessageBurstConfig
    ) -> List[TelemetryEvent]:
        """
        Emits a burst of rapid telemetry frames with elevated message rates and counts.
        """
        burst_events = []
        base_dict = event.data.model_dump()

        # Elevate rate and count
        base_dict["MessageRateInWindow"] = round(base_dict["MessageRateInWindow"] * config.burst_multiplier, 4)
        base_dict["MessageCountInWindow"] = int(base_dict["MessageCountInWindow"] * config.burst_multiplier)
        base_dict["SlidingWindowMeanIntervalSec"] = float(config.compressed_interval_sec)
        base_dict["SlidingWindowMinIntervalSec"] = float(config.compressed_interval_sec / 2.0)

        for _ in range(config.burst_count):
            self._frames_modified += 1
            burst_data = TelemetryData(**base_dict)
            burst_evt = TelemetryEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                source=event.source,
                satellite_id=event.satellite_id,
                event_type=event.event_type,
                data=burst_data,
            )
            burst_events.append(burst_evt)

        return burst_events

    def _handle_message_replay(
        self, event: TelemetryEvent, config: MessageReplayConfig
    ) -> List[TelemetryEvent]:
        """
        Buffers recent telemetry frames and replays them in sequence.
        """
        # Buffer historical frames if buffer not yet full
        if len(self._replay_buffer) < config.buffer_size:
            self._replay_buffer.append(event)
            return [event]

        # Replay historical frame from buffer
        self._frames_modified += 1
        historical_event: TelemetryEvent = self._replay_buffer[self._replay_index]
        
        # Advance replay index within buffer
        self._replay_index = (self._replay_index + 1) % len(self._replay_buffer)
        if self._replay_index == 0:
            self._replay_cycle_count += 1
            if self._replay_cycle_count >= config.replay_cycles:
                # Buffer replay cycle complete, capture current new event
                self._replay_buffer.clear()
                self._replay_cycle_count = 0

        # Construct replayed event preserving historical payload
        replayed_event = TelemetryEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            source=event.source,
            satellite_id=event.satellite_id,
            event_type=event.event_type,
            data=historical_event.data,
        )
        return [replayed_event]
