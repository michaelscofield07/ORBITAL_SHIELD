"""
ORBITAL SHIELD — Access Security Module (Module 4)
Data Input Layer (Adapters).

Decouples data sourcing (Mock JSON/CSV vs Person 1 Simulated Access API)
from the core Access Security Engine detection logic.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
import json
from pathlib import Path
from typing import Any, Dict, List, Union, Optional
import logging

try:
    from models.schemas import AccessLogRecord
except ImportError:
    from ..models.schemas import AccessLogRecord

logger = logging.getLogger("AccessSecurity.Adapter")


class BaseInputAdapter(ABC):
    """
    Abstract Base Class for Access Data Input Adapters.
    Ensures any data source (Mock File, Person 1 REST API, Websocket, etc.)
    converts raw data into standardized `AccessLogRecord` objects.
    """

    @abstractmethod
    def fetch_records(self) -> List[AccessLogRecord]:
        """
        Fetch or ingest access records from the underlying source.
        """
        pass

    @abstractmethod
    def parse_raw_records(self, raw_data: List[Dict[str, Any]]) -> List[AccessLogRecord]:
        """
        Parse raw dictionary/JSON records into normalized AccessLogRecord objects.
        """
        pass


class MockJSONInputAdapter(BaseInputAdapter):
    """
    Adapter that reads mock ground station / operator access data from a JSON file.
    Used for prototype testing and standalone demonstrations.
    """

    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)

    def fetch_records(self) -> List[AccessLogRecord]:
        """
        Reads and parses the JSON file into AccessLogRecord items.
        """
        if not self.file_path.exists():
            raise FileNotFoundError(f"Mock data file not found at: {self.file_path.resolve()}")
        
        with open(self.file_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        
        if not isinstance(raw_data, list):
            raise ValueError("Mock JSON file must contain a JSON array of record objects.")

        return self.parse_raw_records(raw_data)

    def parse_raw_records(self, raw_data: List[Dict[str, Any]]) -> List[AccessLogRecord]:
        """
        Validates and maps raw list of dicts to AccessLogRecord objects.
        """
        records: List[AccessLogRecord] = []
        for index, item in enumerate(raw_data):
            try:
                record = AccessLogRecord(**item)
                records.append(record)
            except Exception as err:
                logger.warning(f"Skipping invalid record at index {index}: {err}")
        return records


def map_api_record_to_access_log(record: Dict[str, Any]) -> AccessLogRecord:
    """
    Translates raw record dictionary from Person 1's API payload format into
    an ORBITAL SHIELD standard AccessLogRecord object.
    
    EXPECTED FIELDS FROM PERSON 1:
    - record_id / id (optional): Unique record identifier
    - timestamp / event_time / date (optional): ISO timestamp string
    - user_id / operator_name / subject (required): Identifier of user/operator
    - source_ip / ip_address (required): IP address string
    - device_id / terminal_id / workstation_id (required): Device identifier string
    - action / event_type (optional, default 'LOGIN'): Action performed
    - result / status / outcome (optional, default 'SUCCESS'): Result status
    - role (optional, default 'operator'): User role
    - previous_role (optional): Previous role if privilege changed
    - resource / endpoint / command (optional): Target resource or command
    - ground_station_id (optional, default 'GS-MAIN-01'): Ground station ID
    - satellite_id (optional, default 'SAT-EO-01'): Satellite ID
    - session_id (optional): Session ID
    """
    normalized_item = {
        "record_id": record.get("record_id") or record.get("id"),
        "timestamp": record.get("timestamp") or record.get("event_time") or record.get("date"),
        "user_id": record.get("user_id") or record.get("operator_name") or record.get("subject"),
        "source_ip": record.get("source_ip") or record.get("ip_address"),
        "device_id": record.get("device_id") or record.get("terminal_id") or record.get("workstation_id"),
        "action": record.get("action") or record.get("event_type") or "LOGIN",
        "result": record.get("result") or record.get("status") or record.get("outcome") or "SUCCESS",
        "role": record.get("role") or "operator",
        "previous_role": record.get("previous_role"),
        "resource": record.get("resource") or record.get("endpoint") or record.get("command"),
        "ground_station_id": record.get("ground_station_id") or "GS-MAIN-01",
        "satellite_id": record.get("satellite_id") or "SAT-EO-01",
        "session_id": record.get("session_id"),
    }
    
    # Filter out None values for default factories in AccessLogRecord if key wasn't present
    cleaned_item = {k: v for k, v in normalized_item.items() if v is not None}
    return AccessLogRecord(**cleaned_item)


class Person1APIInputAdapter(BaseInputAdapter):
    """
    Adapter for Person 1's Live / Simulated Ground Station Access Telemetry REST API.
    Reads connection details from environment variables if not passed explicitly:
      - P1_ACCESS_API_URL
      - P1_ACCESS_API_KEY
      - P1_ACCESS_API_KEY_HEADER (default: X-API-Key)
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        header_name: Optional[str] = None,
        timeout: float = 5.0,
    ):
        import os
        self.api_url = api_url or os.environ.get("P1_ACCESS_API_URL")
        self.api_key = api_key or os.environ.get("P1_ACCESS_API_KEY")
        self.header_name = (
            header_name
            or os.environ.get("P1_ACCESS_API_KEY_HEADER")
            or "X-API-Key"
        )
        self.timeout = timeout

    def is_configured(self) -> bool:
        """Checks whether P1 API mode has required configuration."""
        return bool(self.api_url and self.api_key)

    def fetch_records(self) -> List[AccessLogRecord]:
        """
        Fetches telemetry records from Person 1's REST API using configured headers.
        Handles errors gracefully without crashing the Rule Engine.
        """
        if not self.is_configured():
            logger.info("Person 1 API mode is not fully configured (missing P1_ACCESS_API_URL or P1_ACCESS_API_KEY).")
            return []

        import httpx
        headers = {self.header_name: self.api_key}

        try:
            logger.info(f"Querying Person 1 Access API endpoint: {self.api_url}...")
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(self.api_url, headers=headers)
                response.raise_for_status()
                raw_data = response.json()
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException) as err:
            logger.warning(f"Person 1 API network error / timeout: {err}")
            return []
        except httpx.HTTPStatusError as err:
            logger.warning(f"Person 1 API HTTP status error: {err.response.status_code}")
            return []
        except Exception as err:
            logger.warning(f"Failed to fetch or parse response from Person 1 API: {err}")
            return []

        if isinstance(raw_data, dict):
            # If payload wrapped in e.g. {"records": [...]} or {"data": [...]}
            raw_data = raw_data.get("records") or raw_data.get("data") or raw_data.get("items") or []

        if not isinstance(raw_data, list):
            logger.warning("Person 1 API did not return a valid list of records.")
            return []

        return self.parse_raw_records(raw_data)

    def parse_raw_records(self, raw_data: List[Dict[str, Any]]) -> List[AccessLogRecord]:
        """
        Converts P1 API raw records into AccessLogRecord objects.
        """
        records: List[AccessLogRecord] = []
        for index, item in enumerate(raw_data):
            if not isinstance(item, dict):
                logger.warning(f"Skipping non-dict record at index {index}")
                continue
            try:
                record = map_api_record_to_access_log(item)
                records.append(record)
            except Exception as err:
                logger.warning(f"Skipping malformed API record at index {index}: {err}")
        return records


# Backward compatibility alias
Person1APIAdapterPlaceholder = Person1APIInputAdapter

