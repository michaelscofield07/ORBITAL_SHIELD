"""
ORBITAL_SHIELD - P1 Simulator Unified Gateway

Central coordination layer integrating Telemetry, Scenarios, Commands,
Firmware, and Access Event components into a cohesive simulation workflow.
"""

from datetime import datetime, timezone
from pathlib import Path
import threading
from typing import Any, AsyncGenerator, Dict, List, Optional, Union

from simulator.access.models import AccessAction, AccessEvent, AccessStatus
from simulator.access.simulator import AccessSimulator
from simulator.commands.generator import CommandGenerator
from simulator.commands.models import CommandEvent, CommandStatus, CommandType
from simulator.firmware.models import FirmwareData, FirmwareEvent, FirmwareStatus
from simulator.firmware.simulator import FirmwareSimulator
from simulator.scenarios.engine import ScenarioEngine
from simulator.scenarios.models import BaseScenarioConfig, ScenarioStatus, ScenarioType
from simulator.telemetry.engine import ReplayStatus, TelemetryReplayEngine
from simulator.telemetry.models import HealthResponse, TelemetryEvent

# Standard union for all P1 event types
SimulatorEvent = Union[TelemetryEvent, CommandEvent, FirmwareEvent, AccessEvent]


class SimulatorGateway:
    """
    Unified Gateway for ORBITAL_SHIELD Satellite & Ground Station Simulator (P1).
    Integrates all sub-modules without rewriting their core logic.
    """

    def __init__(
        self,
        dataset_path: Optional[Union[str, Path]] = None,
        satellite_id: str = "SAT-ORBITAL-01",
        telemetry_engine: Optional[TelemetryReplayEngine] = None,
        scenario_engine: Optional[ScenarioEngine] = None,
        command_generator: Optional[CommandGenerator] = None,
        firmware_simulator: Optional[FirmwareSimulator] = None,
        access_simulator: Optional[AccessSimulator] = None,
    ):
        self.satellite_id = satellite_id
        self._lock = threading.RLock()

        # 1. Telemetry Replay Engine
        if telemetry_engine is not None:
            self.telemetry_engine = telemetry_engine
        else:
            if dataset_path is None:
                dataset_path = Path(__file__).resolve().parent / "data" / "consolidated_dataset_raw.csv"
            self.telemetry_engine = TelemetryReplayEngine(
                dataset_path=dataset_path,
                satellite_id=self.satellite_id,
            )

        # 2. Scenario Transformation Engine
        self.scenario_engine = scenario_engine if scenario_engine is not None else ScenarioEngine()

        # 3. Command Simulation Generator
        self.command_generator = (
            command_generator
            if command_generator is not None
            else CommandGenerator(default_satellite_id=self.satellite_id)
        )

        # 4. Firmware Simulator
        self.firmware_simulator = (
            firmware_simulator
            if firmware_simulator is not None
            else FirmwareSimulator(default_satellite_id=self.satellite_id)
        )

        # 5. Access Event Simulator
        self.access_simulator = (
            access_simulator
            if access_simulator is not None
            else AccessSimulator(default_satellite_id=self.satellite_id)
        )

        # Unified event history and latest event cache
        self._unified_history: List[SimulatorEvent] = []
        self._latest_events: Dict[str, Optional[SimulatorEvent]] = {
            "TELEMETRY": None,
            "COMMAND": None,
            "FIRMWARE": None,
            "ACCESS": None,
        }

    # --- Telemetry & Scenario Operations ---

    def get_current_telemetry(self) -> Optional[TelemetryEvent]:
        """
        Retrieves the current telemetry event transformed through the active scenario.
        """
        with self._lock:
            raw_event = self.telemetry_engine.get_current_event()
            if raw_event is None:
                return None
            transformed_list = self.scenario_engine.process_event(raw_event)
            transformed = transformed_list[0] if transformed_list else raw_event
            self._latest_events["TELEMETRY"] = transformed
            return transformed

    def step_telemetry(self) -> Optional[List[TelemetryEvent]]:
        """
        Advances telemetry replay by 1 step, applies active scenario,
        and logs output to the unified event stream.
        """
        with self._lock:
            raw_event = self.telemetry_engine.step()
            if raw_event is None:
                return None
            transformed_events = self.scenario_engine.process_event(raw_event)
            for evt in transformed_events:
                self._record_event(evt)
            return transformed_events

    async def stream_telemetry(
        self,
        limit: Optional[int] = None,
        interval_sec: Optional[float] = None,
        auto_start: bool = True,
    ) -> AsyncGenerator[TelemetryEvent, None]:
        """
        Asynchronously streams telemetry frames through the active scenario pipeline.
        """
        async for raw_evt in self.telemetry_engine.stream_events(
            limit=limit,
            interval_sec=interval_sec,
            auto_start=auto_start,
        ):
            transformed_events = self.scenario_engine.process_event(raw_evt)
            for evt in transformed_events:
                self._record_event(evt)
                yield evt

    def set_scenario(
        self,
        scenario_type: Union[ScenarioType, str],
        config: Optional[BaseScenarioConfig] = None,
    ) -> None:
        """Configures the active simulation scenario."""
        self.scenario_engine.set_scenario(scenario_type, config=config)

    def reset_scenario_to_normal(self) -> None:
        """Resets scenario transformation to baseline NORMAL."""
        self.scenario_engine.reset_to_normal()

    # --- Command Operations ---

    def submit_command(
        self,
        command_type: Union[CommandType, str],
        parameters: Optional[Dict[str, Any]] = None,
        satellite_id: Optional[str] = None,
    ) -> CommandEvent:
        """Submits a ground station command and records it on the gateway bus."""
        with self._lock:
            evt = self.command_generator.submit_command(
                command_type=command_type,
                parameters=parameters,
                satellite_id=satellite_id,
            )
            self._record_event(evt)
            return evt

    def get_command_history(
        self,
        limit: Optional[int] = None,
        command_type: Optional[Union[CommandType, str]] = None,
        status: Optional[Union[CommandStatus, str]] = None,
    ) -> List[CommandEvent]:
        """Retrieves command history from the command generator."""
        return self.command_generator.get_history(
            limit=limit,
            command_type=command_type,
            status=status,
        )

    # --- Firmware Operations ---

    def request_firmware_update(
        self,
        firmware_id_or_version: str,
        satellite_id: Optional[str] = None,
    ) -> FirmwareEvent:
        """Generates an UPDATE_REQUESTED firmware event and records it on the gateway bus."""
        with self._lock:
            evt = self.firmware_simulator.request_firmware_update(
                firmware_id_or_version=firmware_id_or_version,
                satellite_id=satellite_id,
            )
            self._record_event(evt)
            return evt

    def complete_firmware_update(
        self,
        firmware_id_or_version: str,
        satellite_id: Optional[str] = None,
    ) -> FirmwareEvent:
        """Generates an UPDATE_COMPLETED firmware event."""
        with self._lock:
            evt = self.firmware_simulator.complete_firmware_update(
                firmware_id_or_version=firmware_id_or_version,
                satellite_id=satellite_id,
            )
            self._record_event(evt)
            return evt

    def fail_firmware_update(
        self,
        firmware_id_or_version: str,
        satellite_id: Optional[str] = None,
    ) -> FirmwareEvent:
        """Generates an UPDATE_FAILED firmware event."""
        with self._lock:
            evt = self.firmware_simulator.fail_firmware_update(
                firmware_id_or_version=firmware_id_or_version,
                satellite_id=satellite_id,
            )
            self._record_event(evt)
            return evt

    def get_firmware_history(
        self,
        limit: Optional[int] = None,
        status: Optional[Union[FirmwareStatus, str]] = None,
        version: Optional[str] = None,
    ) -> List[FirmwareEvent]:
        """Retrieves firmware update history."""
        return self.firmware_simulator.get_history(
            limit=limit,
            status=status,
            version=version,
        )

    def get_registered_firmware_artifacts(self) -> List[FirmwareData]:
        """Retrieves registered firmware artifacts."""
        return self.firmware_simulator.get_registered_artifacts()

    # --- Access Event Operations ---

    def record_access_event(
        self,
        operator_id: str,
        device_id: str,
        action: Union[AccessAction, str],
        status: Union[AccessStatus, str] = AccessStatus.SUCCESS,
        metadata: Optional[Dict[str, Any]] = None,
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """Records an access event on the gateway bus."""
        with self._lock:
            evt = self.access_simulator.record_access_event(
                operator_id=operator_id,
                device_id=device_id,
                action=action,
                status=status,
                metadata=metadata,
                satellite_id=satellite_id,
            )
            self._record_event(evt)
            return evt

    def get_access_history(
        self,
        limit: Optional[int] = None,
        action: Optional[Union[AccessAction, str]] = None,
        operator_id: Optional[str] = None,
        status: Optional[Union[AccessStatus, str]] = None,
    ) -> List[AccessEvent]:
        """Retrieves operator and device access event history."""
        return self.access_simulator.get_history(
            limit=limit,
            action=action,
            operator_id=operator_id,
            status=status,
        )

    # --- Unified Event Stream & Query Interface ---

    def _record_event(self, event: SimulatorEvent) -> None:
        """Internal recorder caching latest event by event_type and appending to unified log."""
        self._unified_history.append(event)
        self._latest_events[event.event_type] = event

    def get_latest_event(self, event_type: str) -> Optional[SimulatorEvent]:
        """Returns the latest emitted event for a specific event_type (TELEMETRY, COMMAND, FIRMWARE, ACCESS)."""
        with self._lock:
            etype = str(event_type).upper()
            if etype == "TELEMETRY" and self._latest_events.get("TELEMETRY") is None:
                # Pre-fetch current telemetry if none emitted yet
                return self.get_current_telemetry()
            return self._latest_events.get(etype)

    def get_all_latest_events(self) -> Dict[str, Optional[SimulatorEvent]]:
        """Returns a snapshot of the latest event across all 4 event types."""
        with self._lock:
            # Ensure telemetry is populated
            if self._latest_events.get("TELEMETRY") is None:
                self.get_current_telemetry()
            return dict(self._latest_events)

    def get_unified_history(
        self,
        limit: Optional[int] = None,
        event_type: Optional[str] = None,
    ) -> List[SimulatorEvent]:
        """Retrieves unified sequential event history across all P1 modules."""
        with self._lock:
            records = list(self._unified_history)
            if event_type is not None:
                etype = str(event_type).upper()
                records = [r for r in records if r.event_type == etype]

            if limit is not None and limit > 0:
                records = records[-limit:]

            return records

    def get_health(self) -> HealthResponse:
        """Returns overall health and operational status of the simulator gateway."""
        with self._lock:
            telem_status = self.telemetry_engine.get_status()
            return HealthResponse(
                status="healthy",
                timestamp=datetime.now(timezone.utc).isoformat(),
                simulator_state=telem_status.state.value,
                satellite_id=self.satellite_id,
                total_records=telem_status.total_records,
                current_index=telem_status.current_index,
                emitted_count=telem_status.emitted_count,
            )

    def get_system_status(self) -> Dict[str, Any]:
        """Returns comprehensive status snapshot across all 5 simulator components."""
        with self._lock:
            return {
                "satellite_id": self.satellite_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "telemetry": self.telemetry_engine.get_status().__dict__,
                "scenarios": self.scenario_engine.get_status().model_dump(),
                "commands_count": len(self.command_generator.get_history()),
                "firmware_events_count": len(self.firmware_simulator.get_history()),
                "access_events_count": len(self.access_simulator.get_history()),
                "total_unified_events": len(self._unified_history),
            }
