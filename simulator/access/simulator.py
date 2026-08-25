"""
ORBITAL_SHIELD - Access Event Simulator

Manages generation, validation, and history tracking of operator and device access events
at the Ground Station.
"""

from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional, Union
import uuid

from .models import AccessAction, AccessData, AccessEvent, AccessStatus


class AccessSimulator:
    """
    Modular simulator for ground station operator and device access activity.
    """

    def __init__(self, default_satellite_id: str = "SAT-ORBITAL-01"):
        self.default_satellite_id = default_satellite_id
        self._history: List[AccessEvent] = []
        self._lock = threading.RLock()

    def create_access_event(
        self,
        operator_id: str,
        device_id: str,
        action: Union[AccessAction, str],
        status: Union[AccessStatus, str] = AccessStatus.SUCCESS,
        metadata: Optional[Dict[str, Any]] = None,
        satellite_id: Optional[str] = None,
        access_id: Optional[str] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        source: str = "GROUND_STATION_SIMULATOR",
    ) -> AccessEvent:
        """
        Constructs and validates an AccessEvent instance without modifying event history.
        """
        # Validate action
        if isinstance(action, str):
            try:
                action_enum = AccessAction(action)
            except ValueError:
                valid_actions = [a.value for a in AccessAction]
                raise ValueError(
                    f"Invalid action '{action}'. Must be one of: {valid_actions}"
                )
        elif isinstance(action, AccessAction):
            action_enum = action
        else:
            raise TypeError(f"Expected AccessAction or str, got {type(action)}")

        # Validate status
        if isinstance(status, str):
            status_enum = AccessStatus(status)
        elif isinstance(status, AccessStatus):
            status_enum = status
        else:
            raise TypeError(f"Expected AccessStatus or str, got {type(status)}")

        meta = dict(metadata) if metadata is not None else {}
        sat_id = satellite_id if satellite_id is not None else self.default_satellite_id
        gen_access_id = access_id if access_id is not None else f"ACC-{uuid.uuid4().hex[:10].upper()}"
        gen_event_id = event_id if event_id is not None else str(uuid.uuid4())
        gen_timestamp = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()

        access_data = AccessData(
            access_id=gen_access_id,
            operator_id=str(operator_id),
            device_id=str(device_id),
            action=action_enum,
            status=status_enum,
            metadata=meta,
        )

        return AccessEvent(
            event_id=gen_event_id,
            timestamp=gen_timestamp,
            source=source,  # type: ignore
            satellite_id=sat_id,
            event_type="ACCESS",
            data=access_data,
        )

    def record_access_event(
        self,
        operator_id: str,
        device_id: str,
        action: Union[AccessAction, str],
        status: Union[AccessStatus, str] = AccessStatus.SUCCESS,
        metadata: Optional[Dict[str, Any]] = None,
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """
        Creates and appends an access event to the sequential history log.
        """
        with self._lock:
            event = self.create_access_event(
                operator_id=operator_id,
                device_id=device_id,
                action=action,
                status=status,
                metadata=metadata,
                satellite_id=satellite_id,
            )
            self._history.append(event)
            return event

    def submit_event(self, event: AccessEvent) -> AccessEvent:
        """
        Submits an already constructed AccessEvent to the history log.
        """
        with self._lock:
            if not isinstance(event, AccessEvent):
                raise TypeError(f"Expected AccessEvent, got {type(event)}")
            self._history.append(event)
            return event

    # --- Convenience Factory Helpers for All 6 Access Event Types ---

    def login(
        self,
        operator_id: str,
        device_id: str,
        ip_address: Optional[str] = None,
        auth_method: str = "PASSWORD_MFA",
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """Simulates a successful operator login event."""
        meta: Dict[str, Any] = {"auth_method": auth_method}
        if ip_address is not None:
            meta["ip_address"] = ip_address

        return self.record_access_event(
            operator_id=operator_id,
            device_id=device_id,
            action=AccessAction.LOGIN,
            status=AccessStatus.SUCCESS,
            metadata=meta,
            satellite_id=satellite_id,
        )

    def failed_login(
        self,
        operator_id: str,
        device_id: str,
        reason: str = "INVALID_CREDENTIALS",
        ip_address: Optional[str] = None,
        attempt_count: int = 1,
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """Simulates a failed operator login attempt."""
        meta: Dict[str, Any] = {
            "reason": reason,
            "attempt_count": attempt_count,
        }
        if ip_address is not None:
            meta["ip_address"] = ip_address

        return self.record_access_event(
            operator_id=operator_id,
            device_id=device_id,
            action=AccessAction.FAILED_LOGIN,
            status=AccessStatus.FAILURE,
            metadata=meta,
            satellite_id=satellite_id,
        )

    def logout(
        self,
        operator_id: str,
        device_id: str,
        session_duration_sec: Optional[int] = None,
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """Simulates an operator logout event."""
        meta: Dict[str, Any] = {}
        if session_duration_sec is not None:
            meta["session_duration_sec"] = session_duration_sec

        return self.record_access_event(
            operator_id=operator_id,
            device_id=device_id,
            action=AccessAction.LOGOUT,
            status=AccessStatus.SUCCESS,
            metadata=meta,
            satellite_id=satellite_id,
        )

    def new_device(
        self,
        operator_id: str,
        device_id: str,
        device_type: str = "WORKSTATION",
        os_platform: str = "LINUX",
        mac_address: Optional[str] = None,
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """Simulates a new unrecognized device registration/access event."""
        meta: Dict[str, Any] = {
            "device_type": device_type,
            "os_platform": os_platform,
        }
        if mac_address is not None:
            meta["mac_address"] = mac_address

        return self.record_access_event(
            operator_id=operator_id,
            device_id=device_id,
            action=AccessAction.NEW_DEVICE,
            status=AccessStatus.SUCCESS,
            metadata=meta,
            satellite_id=satellite_id,
        )

    def privilege_change(
        self,
        operator_id: str,
        device_id: str,
        previous_role: str,
        new_role: str,
        authorized_by: Optional[str] = None,
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """Simulates an operator role / privilege level elevation or change."""
        meta: Dict[str, Any] = {
            "previous_role": previous_role,
            "new_role": new_role,
        }
        if authorized_by is not None:
            meta["authorized_by"] = authorized_by

        return self.record_access_event(
            operator_id=operator_id,
            device_id=device_id,
            action=AccessAction.PRIVILEGE_CHANGE,
            status=AccessStatus.SUCCESS,
            metadata=meta,
            satellite_id=satellite_id,
        )

    def command_access(
        self,
        operator_id: str,
        device_id: str,
        command_type: str,
        command_id: Optional[str] = None,
        channel: str = "UPLINK_PRIMARY",
        satellite_id: Optional[str] = None,
    ) -> AccessEvent:
        """Simulates an operator requesting access to send satellite commands."""
        meta: Dict[str, Any] = {
            "command_type": command_type,
            "channel": channel,
        }
        if command_id is not None:
            meta["command_id"] = command_id

        return self.record_access_event(
            operator_id=operator_id,
            device_id=device_id,
            action=AccessAction.COMMAND_ACCESS,
            status=AccessStatus.SUCCESS,
            metadata=meta,
            satellite_id=satellite_id,
        )

    # --- History Queries & Filtering ---

    def get_history(
        self,
        limit: Optional[int] = None,
        action: Optional[Union[AccessAction, str]] = None,
        operator_id: Optional[str] = None,
        status: Optional[Union[AccessStatus, str]] = None,
    ) -> List[AccessEvent]:
        """Retrieves sequential access event history with optional filtering."""
        with self._lock:
            records = list(self._history)

            if action is not None:
                action_val = action.value if isinstance(action, AccessAction) else action
                records = [r for r in records if r.data.action.value == action_val]

            if operator_id is not None:
                records = [r for r in records if r.data.operator_id == operator_id]

            if status is not None:
                status_val = status.value if isinstance(status, AccessStatus) else status
                records = [r for r in records if r.data.status.value == status_val]

            if limit is not None and limit > 0:
                records = records[-limit:]

            return records

    def get_event_by_id(self, event_id: str) -> Optional[AccessEvent]:
        """Looks up an access event by its unique event_id."""
        with self._lock:
            for evt in self._history:
                if evt.event_id == event_id or evt.data.access_id == event_id:
                    return evt
            return None

    def get_events_by_operator(self, operator_id: str) -> List[AccessEvent]:
        """Returns all access events associated with a specific operator ID."""
        return self.get_history(operator_id=operator_id)

    def clear_history(self) -> None:
        """Clears all access event history."""
        with self._lock:
            self._history.clear()
