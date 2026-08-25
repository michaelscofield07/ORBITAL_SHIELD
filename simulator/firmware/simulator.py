"""
ORBITAL_SHIELD - Firmware Simulator

Manages registration of firmware artifacts, generation of firmware update events,
and lifecycle status tracking (REQUESTED, IN_PROGRESS, COMPLETED, FAILED).
"""

from datetime import datetime, timezone
import hashlib
import threading
from typing import Any, Dict, List, Optional, Union
import uuid

from .models import FirmwareData, FirmwareEvent, FirmwareStatus


class FirmwareSimulator:
    """
    Modular simulator representing satellite firmware artifacts and update activity.
    """

    def __init__(self, default_satellite_id: str = "SAT-ORBITAL-01", auto_register_defaults: bool = True):
        self.default_satellite_id = default_satellite_id
        self._artifacts: Dict[str, FirmwareData] = {}
        self._history: List[FirmwareEvent] = []
        self._lock = threading.RLock()

        if auto_register_defaults:
            self._register_default_artifacts()

    def _register_default_artifacts(self) -> None:
        """Registers default baseline firmware artifacts (firmware_v1, firmware_v2)."""
        # Baseline firmware v1
        self.register_artifact(
            version="firmware_v1",
            artifact="orbital_obc_firmware_v1.0.bin",
            size_bytes=524288,
            firmware_id="FW-ORBITAL-V1",
        )
        # Next-gen firmware v2
        self.register_artifact(
            version="firmware_v2",
            artifact="orbital_obc_firmware_v2.0.bin",
            size_bytes=786432,
            firmware_id="FW-ORBITAL-V2",
        )

    def register_artifact(
        self,
        version: str,
        artifact: str,
        size_bytes: int,
        hash_val: Optional[str] = None,
        firmware_id: Optional[str] = None,
        raw_payload: Optional[bytes] = None,
        status: FirmwareStatus = FirmwareStatus.REGISTERED,
    ) -> FirmwareData:
        """
        Registers a firmware artifact into the simulator's artifact repository.
        Computes SHA-256 hash automatically if not explicitly provided.
        """
        with self._lock:
            if size_bytes < 0:
                raise ValueError("size_bytes must be greater than or equal to 0.")

            # Generate unique ID if not provided
            fid = firmware_id if firmware_id is not None else f"FW-{uuid.uuid4().hex[:10].upper()}"

            # Calculate SHA-256 hash if not given
            if hash_val is not None:
                computed_hash = hash_val
            elif raw_payload is not None:
                computed_hash = hashlib.sha256(raw_payload).hexdigest()
            else:
                seed_str = f"{fid}:{version}:{artifact}:{size_bytes}"
                computed_hash = hashlib.sha256(seed_str.encode("utf-8")).hexdigest()

            fw_data = FirmwareData(
                firmware_id=fid,
                version=version,
                artifact=artifact,
                size_bytes=size_bytes,
                hash=computed_hash,
                status=status,
            )

            # Index by firmware_id and version alias
            self._artifacts[fid] = fw_data
            self._artifacts[version] = fw_data
            return fw_data

    def get_artifact(self, firmware_id_or_version: str) -> Optional[FirmwareData]:
        """Looks up a registered firmware artifact by ID or version alias."""
        with self._lock:
            return self._artifacts.get(firmware_id_or_version)

    def get_registered_artifacts(self) -> List[FirmwareData]:
        """Returns unique list of all registered firmware artifacts."""
        with self._lock:
            seen_ids = set()
            unique_artifacts = []
            for art in self._artifacts.values():
                if art.firmware_id not in seen_ids:
                    seen_ids.add(art.firmware_id)
                    unique_artifacts.append(art)
            return unique_artifacts

    def create_firmware_event(
        self,
        firmware_id_or_version: str,
        status: FirmwareStatus = FirmwareStatus.UPDATE_REQUESTED,
        satellite_id: Optional[str] = None,
        source: str = "GROUND_STATION_SIMULATOR",
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> FirmwareEvent:
        """
        Creates a validated FirmwareEvent for a registered or dynamic firmware artifact.
        """
        with self._lock:
            artifact = self.get_artifact(firmware_id_or_version)
            if artifact is None:
                raise KeyError(
                    f"Firmware artifact '{firmware_id_or_version}' not registered in simulator."
                )

            sat_id = satellite_id if satellite_id is not None else self.default_satellite_id
            gen_event_id = event_id if event_id is not None else str(uuid.uuid4())
            gen_timestamp = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()

            # Copy data with updated status
            data_with_status = artifact.model_copy(update={"status": status})

            return FirmwareEvent(
                event_id=gen_event_id,
                timestamp=gen_timestamp,
                source=source,  # type: ignore
                satellite_id=sat_id,
                event_type="FIRMWARE",
                data=data_with_status,
            )

    def request_firmware_update(
        self,
        firmware_id_or_version: str,
        satellite_id: Optional[str] = None,
    ) -> FirmwareEvent:
        """Generates and logs an UPDATE_REQUESTED event."""
        with self._lock:
            event = self.create_firmware_event(
                firmware_id_or_version=firmware_id_or_version,
                status=FirmwareStatus.UPDATE_REQUESTED,
                satellite_id=satellite_id,
                source="GROUND_STATION_SIMULATOR",
            )
            self._history.append(event)
            return event

    def start_firmware_update(
        self,
        firmware_id_or_version: str,
        satellite_id: Optional[str] = None,
    ) -> FirmwareEvent:
        """Generates and logs an UPDATE_IN_PROGRESS event."""
        with self._lock:
            event = self.create_firmware_event(
                firmware_id_or_version=firmware_id_or_version,
                status=FirmwareStatus.UPDATE_IN_PROGRESS,
                satellite_id=satellite_id,
                source="SATELLITE_SIMULATOR",
            )
            self._history.append(event)
            return event

    def complete_firmware_update(
        self,
        firmware_id_or_version: str,
        satellite_id: Optional[str] = None,
    ) -> FirmwareEvent:
        """Generates and logs an UPDATE_COMPLETED event."""
        with self._lock:
            event = self.create_firmware_event(
                firmware_id_or_version=firmware_id_or_version,
                status=FirmwareStatus.UPDATE_COMPLETED,
                satellite_id=satellite_id,
                source="SATELLITE_SIMULATOR",
            )
            self._history.append(event)
            return event

    def fail_firmware_update(
        self,
        firmware_id_or_version: str,
        satellite_id: Optional[str] = None,
    ) -> FirmwareEvent:
        """Generates and logs an UPDATE_FAILED event."""
        with self._lock:
            event = self.create_firmware_event(
                firmware_id_or_version=firmware_id_or_version,
                status=FirmwareStatus.UPDATE_FAILED,
                satellite_id=satellite_id,
                source="SATELLITE_SIMULATOR",
            )
            self._history.append(event)
            return event

    def submit_event(self, event: FirmwareEvent) -> FirmwareEvent:
        """Submits a pre-constructed FirmwareEvent to the history log."""
        with self._lock:
            if not isinstance(event, FirmwareEvent):
                raise TypeError(f"Expected FirmwareEvent, got {type(event)}")
            self._history.append(event)
            return event

    def get_history(
        self,
        limit: Optional[int] = None,
        status: Optional[Union[FirmwareStatus, str]] = None,
        version: Optional[str] = None,
    ) -> List[FirmwareEvent]:
        """Retrieves sequential firmware event history with optional filtering."""
        with self._lock:
            records = list(self._history)

            if status is not None:
                status_val = status.value if isinstance(status, FirmwareStatus) else status
                records = [r for r in records if r.data.status.value == status_val]

            if version is not None:
                records = [r for r in records if r.data.version == version]

            if limit is not None and limit > 0:
                records = records[-limit:]

            return records

    def clear_history(self) -> None:
        """Clears firmware event history."""
        with self._lock:
            self._history.clear()
