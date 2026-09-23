"""
ORBITAL_SHIELD - Command Generator & Simulator

Manages generation, validation, submission, and sequential history tracking of
commands issued from Ground Station to simulated satellites.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional, Union
import uuid

from .models import CommandData, CommandEvent, CommandStatus, CommandType


class CommandGenerator:
    """
    Modular Command Simulator for generating, validating, and tracking ground station commands.
    """

    def __init__(self, default_satellite_id: str = "SAT-ORBITAL-01"):
        self.default_satellite_id = default_satellite_id
        self._history: List[CommandEvent] = []
        self._lock = threading.RLock()

    def create_command(
        self,
        command_type: Union[CommandType, str],
        parameters: Optional[Dict[str, Any]] = None,
        status: CommandStatus = CommandStatus.PENDING,
        satellite_id: Optional[str] = None,
        command_id: Optional[str] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> CommandEvent:
        """
        Constructs and validates a CommandEvent instance without modifying command history.
        """
        # Validate command type
        if isinstance(command_type, str):
            try:
                cmd_type_enum = CommandType(command_type)
            except ValueError:
                valid_types = [t.value for t in CommandType]
                raise ValueError(
                    f"Invalid command_type '{command_type}'. Must be one of: {valid_types}"
                )
        elif isinstance(command_type, CommandType):
            cmd_type_enum = command_type
        else:
            raise TypeError(f"Expected CommandType or str, got {type(command_type)}")

        params = dict(parameters) if parameters is not None else {}
        sat_id = satellite_id if satellite_id is not None else self.default_satellite_id
        gen_cmd_id = command_id if command_id is not None else f"CMD-{uuid.uuid4().hex[:12].upper()}"
        gen_event_id = event_id if event_id is not None else str(uuid.uuid4())
        gen_timestamp = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()

        cmd_data = CommandData(
            command_id=gen_cmd_id,
            command_type=cmd_type_enum,
            parameters=params,
            status=status,
        )

        return CommandEvent(
            event_id=gen_event_id,
            timestamp=gen_timestamp,
            source="GROUND_STATION_SIMULATOR",
            satellite_id=sat_id,
            event_type="COMMAND",
            data=cmd_data,
        )

    def submit_command(
        self,
        command_type: Union[CommandType, str],
        parameters: Optional[Dict[str, Any]] = None,
        status: CommandStatus = CommandStatus.PENDING,
        satellite_id: Optional[str] = None,
        command_id: Optional[str] = None,
    ) -> CommandEvent:
        """
        Creates and submits a command to the sequential command history.
        """
        with self._lock:
            event = self.create_command(
                command_type=command_type,
                parameters=parameters,
                status=status,
                satellite_id=satellite_id,
                command_id=command_id,
            )
            self._history.append(event)
            return event

    def submit_event(self, command_event: CommandEvent) -> CommandEvent:
        """
        Submits an already constructed CommandEvent to the command history.
        """
        with self._lock:
            if not isinstance(command_event, CommandEvent):
                raise TypeError(f"Expected CommandEvent instance, got {type(command_event)}")
            self._history.append(command_event)
            return command_event

    def get_history(
        self,
        limit: Optional[int] = None,
        command_type: Optional[Union[CommandType, str]] = None,
        status: Optional[Union[CommandStatus, str]] = None,
    ) -> List[CommandEvent]:
        """
        Retrieves sequential command history with optional filtering.
        """
        with self._lock:
            records = list(self._history)

            if command_type is not None:
                type_val = command_type.value if isinstance(command_type, CommandType) else command_type
                records = [r for r in records if r.data.command_type.value == type_val]

            if status is not None:
                status_val = status.value if isinstance(status, CommandStatus) else status
                records = [r for r in records if r.data.status.value == status_val]

            if limit is not None and limit > 0:
                records = records[-limit:]

            return records

    def get_command_by_id(self, command_id: str) -> Optional[CommandEvent]:
        """
        Looks up a command by its unique command_id.
        """
        with self._lock:
            for cmd in self._history:
                if cmd.data.command_id == command_id:
                    return cmd
            return None

    def update_command_status(
        self, command_id: str, new_status: Union[CommandStatus, str]
    ) -> Optional[CommandEvent]:
        """
        Updates the lifecycle status of an existing command in history.
        """
        with self._lock:
            if isinstance(new_status, str):
                new_status = CommandStatus(new_status)

            for i, cmd in enumerate(self._history):
                if cmd.data.command_id == command_id:
                    updated_data = cmd.data.model_copy(update={"status": new_status})
                    updated_event = cmd.model_copy(update={"data": updated_data})
                    self._history[i] = updated_event
                    return updated_event
            return None

    def clear_history(self) -> None:
        """Clears all command history."""
        with self._lock:
            self._history.clear()

    # --- Convenience Factory Helpers for Supported Command Types ---

    def create_adjust_camera(
        self,
        zoom: float = 1.0,
        pan: float = 0.0,
        tilt: float = 0.0,
        exposure_ms: int = 100,
        satellite_id: Optional[str] = None,
    ) -> CommandEvent:
        """Factory for ADJUST_CAMERA command."""
        params = {
            "zoom": float(zoom),
            "pan": float(pan),
            "tilt": float(tilt),
            "exposure_ms": int(exposure_ms),
        }
        return self.create_command(
            command_type=CommandType.ADJUST_CAMERA,
            parameters=params,
            satellite_id=satellite_id,
        )

    def create_change_orbit(
        self,
        delta_v_ms: float,
        target_altitude_km: float,
        inclination_deg: Optional[float] = None,
        satellite_id: Optional[str] = None,
    ) -> CommandEvent:
        """Factory for CHANGE_ORBIT command."""
        params: Dict[str, Any] = {
            "delta_v_ms": float(delta_v_ms),
            "target_altitude_km": float(target_altitude_km),
        }
        if inclination_deg is not None:
            params["inclination_deg"] = float(inclination_deg)
        return self.create_command(
            command_type=CommandType.CHANGE_ORBIT,
            parameters=params,
            satellite_id=satellite_id,
        )

    def create_start_sensor(
        self,
        sensor_id: str = "SENSOR-OPTICAL-01",
        sample_rate_hz: float = 10.0,
        satellite_id: Optional[str] = None,
    ) -> CommandEvent:
        """Factory for START_SENSOR command."""
        params = {
            "sensor_id": str(sensor_id),
            "sample_rate_hz": float(sample_rate_hz),
        }
        return self.create_command(
            command_type=CommandType.START_SENSOR,
            parameters=params,
            satellite_id=satellite_id,
        )

    def create_stop_sensor(
        self,
        sensor_id: str = "SENSOR-OPTICAL-01",
        satellite_id: Optional[str] = None,
    ) -> CommandEvent:
        """Factory for STOP_SENSOR command."""
        params = {
            "sensor_id": str(sensor_id),
        }
        return self.create_command(
            command_type=CommandType.STOP_SENSOR,
            parameters=params,
            satellite_id=satellite_id,
        )

    def create_reboot(
        self,
        mode: str = "WARM",
        delay_sec: int = 0,
        satellite_id: Optional[str] = None,
    ) -> CommandEvent:
        """Factory for REBOOT command."""
        params = {
            "mode": str(mode).upper(),
            "delay_sec": int(delay_sec),
        }
        return self.create_command(
            command_type=CommandType.REBOOT,
            parameters=params,
            satellite_id=satellite_id,
        )
