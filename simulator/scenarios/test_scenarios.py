"""
Unit tests for ORBITAL_SHIELD Scenario Engine.
"""

from pathlib import Path
import pandas as pd
import pytest

from simulator.scenarios.engine import ScenarioEngine
from simulator.scenarios.models import (
    MessageBurstConfig,
    MessageReplayConfig,
    ScenarioType,
    TelemetryAnomalyConfig,
)
from simulator.telemetry.converter import row_to_telemetry_event
from simulator.telemetry.models import TelemetryEvent


@pytest.fixture
def sample_telemetry_event():
    """Generates a standard TelemetryEvent from real dataset row."""
    dataset_path = Path(__file__).resolve().parent.parent / "data" / "consolidated_dataset_raw.csv"
    df = pd.read_csv(dataset_path, nrows=5)
    return row_to_telemetry_event(df.iloc[0])


@pytest.fixture
def sample_event_sequence():
    """Generates a sequence of 5 standard TelemetryEvents."""
    dataset_path = Path(__file__).resolve().parent.parent / "data" / "consolidated_dataset_raw.csv"
    df = pd.read_csv(dataset_path, nrows=5)
    return [row_to_telemetry_event(df.iloc[i]) for i in range(5)]


def test_default_scenario_is_normal(sample_telemetry_event):
    """Test engine defaults to NORMAL and does not alter events."""
    engine = ScenarioEngine()
    status = engine.get_status()

    assert status.active_scenario == ScenarioType.NORMAL
    assert status.is_active is False
    assert status.frames_processed == 0
    assert status.frames_modified == 0

    processed = engine.process_event(sample_telemetry_event)
    assert len(processed) == 1
    assert processed[0] == sample_telemetry_event
    assert engine.get_status().frames_processed == 1
    assert engine.get_status().frames_modified == 0


def test_explicit_activation_and_reset(sample_telemetry_event):
    """Test scenarios must be explicitly activated and can be reset."""
    engine = ScenarioEngine()

    engine.set_scenario(ScenarioType.TELEMETRY_ANOMALY)
    assert engine.active_scenario == ScenarioType.TELEMETRY_ANOMALY
    assert engine.get_status().is_active is True

    engine.reset_to_normal()
    assert engine.active_scenario == ScenarioType.NORMAL
    assert engine.get_status().is_active is False


def test_telemetry_anomaly_scenario(sample_telemetry_event):
    """Test TELEMETRY_ANOMALY modifies memory, page faults, and errors properly."""
    engine = ScenarioEngine()
    config = TelemetryAnomalyConfig(
        memory_multiplier=3.0,
        inject_page_faults=64,
        corrupt_command_errors=2,
        seed=123,
    )
    engine.set_scenario(ScenarioType.TELEMETRY_ANOMALY, config=config)

    orig_mem = sample_telemetry_event.data.MemoryAnonMB
    results = engine.process_event(sample_telemetry_event)

    assert len(results) == 1
    anom_evt = results[0]
    assert isinstance(anom_evt, TelemetryEvent)
    assert anom_evt.source == "SATELLITE_SIMULATOR"
    assert anom_evt.event_type == "TELEMETRY"

    # Verify specific anomalies
    assert pytest.approx(anom_evt.data.MemoryAnonMB, 1e-4) == round(orig_mem * 3.0, 6)
    assert anom_evt.data.MemoryPageFaults == 64
    assert anom_evt.data.CommandErrorCounter == 2
    assert engine.get_status().frames_modified == 1


def test_deterministic_reproducibility_with_seed(sample_telemetry_event):
    """Test that two engines with identical seeds produce identical modifications."""
    engine1 = ScenarioEngine()
    engine2 = ScenarioEngine()

    cfg1 = TelemetryAnomalyConfig(seed=999)
    cfg2 = TelemetryAnomalyConfig(seed=999)

    engine1.set_scenario(ScenarioType.TELEMETRY_ANOMALY, config=cfg1)
    engine2.set_scenario(ScenarioType.TELEMETRY_ANOMALY, config=cfg2)

    res1 = engine1.process_event(sample_telemetry_event)[0]
    res2 = engine2.process_event(sample_telemetry_event)[0]

    # Field values must be 100% identical
    assert res1.data.model_dump() == res2.data.model_dump()


def test_message_burst_scenario(sample_telemetry_event):
    """Test MESSAGE_BURST emits multiple rapid frames with elevated rates."""
    engine = ScenarioEngine()
    config = MessageBurstConfig(
        burst_multiplier=5.0,
        compressed_interval_sec=0.002,
        burst_count=4,
    )
    engine.set_scenario(ScenarioType.MESSAGE_BURST, config=config)

    orig_rate = sample_telemetry_event.data.MessageRateInWindow
    orig_count = sample_telemetry_event.data.MessageCountInWindow

    burst_results = engine.process_event(sample_telemetry_event)

    assert len(burst_results) == 4
    for evt in burst_results:
        assert isinstance(evt, TelemetryEvent)
        assert pytest.approx(evt.data.MessageRateInWindow, 1e-4) == orig_rate * 5.0
        assert evt.data.MessageCountInWindow == int(orig_count * 5.0)
        assert evt.data.SlidingWindowMeanIntervalSec == 0.002

    assert engine.get_status().frames_modified == 4


def test_message_replay_scenario(sample_event_sequence):
    """Test MESSAGE_REPLAY captures buffer and re-emits historical frames."""
    engine = ScenarioEngine()
    config = MessageReplayConfig(buffer_size=2, replay_cycles=1)
    engine.set_scenario(ScenarioType.MESSAGE_REPLAY, config=config)

    ev0, ev1, ev2, ev3, ev4 = sample_event_sequence

    # First 2 events fill the buffer
    r0 = engine.process_event(ev0)
    assert r0[0].data.MsgId == ev0.data.MsgId
    r1 = engine.process_event(ev1)
    assert r1[0].data.MsgId == ev1.data.MsgId

    # 3rd event should replay buffered ev0
    r2 = engine.process_event(ev2)
    assert r2[0].data.MsgId == ev0.data.MsgId
    assert r2[0].data.CmdCode == ev0.data.CmdCode

    # 4th event should replay buffered ev1
    r3 = engine.process_event(ev3)
    assert r3[0].data.MsgId == ev1.data.MsgId
    assert r3[0].data.CmdCode == ev1.data.CmdCode


def test_scenario_duration_frames_auto_reset(sample_telemetry_event):
    """Test scenario with duration_frames automatically resets to NORMAL after frame limit."""
    engine = ScenarioEngine()
    config = TelemetryAnomalyConfig(duration_frames=2)
    engine.set_scenario(ScenarioType.TELEMETRY_ANOMALY, config=config)

    # Frame 1: Anomaly
    res1 = engine.process_event(sample_telemetry_event)
    assert res1[0].data.MemoryPageFaults > 0

    # Frame 2: Anomaly
    res2 = engine.process_event(sample_telemetry_event)
    assert res2[0].data.MemoryPageFaults > 0

    # Frame 3: Automatically reverts to NORMAL
    res3 = engine.process_event(sample_telemetry_event)
    assert res3[0].data.MemoryPageFaults == 0
    assert engine.active_scenario == ScenarioType.NORMAL


def test_dataset_source_not_modified():
    """Verify source CSV remains untouched after scenario executions."""
    dataset_path = Path(__file__).resolve().parent.parent / "data" / "consolidated_dataset_raw.csv"
    df_before = pd.read_csv(dataset_path, nrows=5)

    engine = ScenarioEngine()
    engine.set_scenario(ScenarioType.TELEMETRY_ANOMALY)
    for idx, row in df_before.iterrows():
        evt = row_to_telemetry_event(row)
        engine.process_event(evt)

    df_after = pd.read_csv(dataset_path, nrows=5)
    pd.testing.assert_frame_equal(df_before, df_after)
