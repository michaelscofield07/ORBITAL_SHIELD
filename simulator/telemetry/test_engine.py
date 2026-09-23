"""
Unit tests for ORBITAL_SHIELD Telemetry Replay Engine.
"""

import asyncio
from pathlib import Path
import time
import pandas as pd
import pytest

from simulator.telemetry.engine import TelemetryReplayEngine, ReplayState
from simulator.telemetry.models import TelemetryEvent


@pytest.fixture
def mini_df():
    """Returns a mini 3-row DataFrame with exact schema for fast testing."""
    dataset_path = Path(__file__).resolve().parent.parent / "data" / "consolidated_dataset_raw.csv"
    df = pd.read_csv(dataset_path, nrows=3)
    return df


def test_engine_init_with_real_dataset():
    """Test engine loads the consolidated dataset properly."""
    engine = TelemetryReplayEngine()
    status = engine.get_status()

    assert status.total_records == 25000
    assert status.current_index == 0
    assert status.state == ReplayState.STOPPED
    assert status.progress_pct == 0.0
    assert status.speed_multiplier == 1.0


def test_engine_sequential_step(mini_df):
    """Test sequential stepping through records."""
    engine = TelemetryReplayEngine(dataframe=mini_df)

    # Step 1
    ev1 = engine.step()
    assert isinstance(ev1, TelemetryEvent)
    assert engine.current_index == 1
    assert engine.emitted_count == 1
    assert ev1.data.MsgId == int(mini_df.iloc[0]["MsgId"])

    # Step 2
    ev2 = engine.step()
    assert isinstance(ev2, TelemetryEvent)
    assert engine.current_index == 2
    assert engine.emitted_count == 2
    assert ev2.data.MsgId == int(mini_df.iloc[1]["MsgId"])

    # Step 3
    ev3 = engine.step()
    assert isinstance(ev3, TelemetryEvent)
    assert engine.current_index == 3
    assert engine.state == ReplayState.COMPLETED

    # Step 4 (End of dataset reached with loop=False)
    ev4 = engine.step()
    assert ev4 is None
    assert engine.state == ReplayState.COMPLETED


def test_engine_loop_behavior(mini_df):
    """Test that engine loops back to index 0 when loop=True."""
    engine = TelemetryReplayEngine(dataframe=mini_df, loop=True)

    ev1 = engine.step()
    ev2 = engine.step()
    ev3 = engine.step()
    # 4th step should loop back to 1st record
    ev4 = engine.step()

    assert ev4 is not None
    assert ev4.data.MsgId == ev1.data.MsgId
    assert engine.current_index == 1
    assert engine.emitted_count == 4


def test_engine_start_pause_stop_reset(mini_df):
    """Test start, pause, stop, and reset transitions."""
    engine = TelemetryReplayEngine(dataframe=mini_df)
    assert engine.state == ReplayState.STOPPED

    engine.start()
    assert engine.state == ReplayState.RUNNING

    engine.step()
    assert engine.current_index == 1
    assert engine.emitted_count == 1

    engine.pause()
    assert engine.state == ReplayState.PAUSED
    assert engine.current_index == 1

    engine.stop()
    assert engine.state == ReplayState.STOPPED
    assert engine.current_index == 0

    # Test reset clears emitted count as well
    engine.step()
    assert engine.emitted_count == 2
    engine.reset()
    assert engine.state == ReplayState.STOPPED
    assert engine.current_index == 0
    assert engine.emitted_count == 0


def test_speed_and_interval_controls():
    """Test configuring playback speeds and intervals."""
    engine = TelemetryReplayEngine(base_interval_sec=1.0, speed_multiplier=1.0)
    assert engine.effective_interval_sec == 1.0

    engine.set_speed(2.0)
    assert engine.speed_multiplier == 2.0
    assert pytest.approx(engine.effective_interval_sec, 1e-6) == 0.5

    engine.set_speed(10.0)
    assert pytest.approx(engine.effective_interval_sec, 1e-6) == 0.1

    with pytest.raises(ValueError):
        engine.set_speed(0.0)

    with pytest.raises(ValueError):
        engine.set_base_interval(-1.0)


def test_seek_controls(mini_df):
    """Test seeking to specific record indices."""
    engine = TelemetryReplayEngine(dataframe=mini_df)

    engine.seek(2)
    assert engine.current_index == 2

    # Clamp upper bound
    engine.seek(100)
    assert engine.current_index == 2

    # Clamp lower bound
    engine.seek(-5)
    assert engine.current_index == 0


def test_callback_listener(mini_df):
    """Test registered callbacks receive emitted events."""
    engine = TelemetryReplayEngine(dataframe=mini_df)
    received = []

    def on_telemetry(evt: TelemetryEvent):
        received.append(evt)

    engine.register_callback(on_telemetry)
    engine.step()
    engine.step()

    assert len(received) == 2
    assert all(isinstance(e, TelemetryEvent) for e in received)

    # Unregister callback
    engine.unregister_callback(on_telemetry)
    engine.step()
    assert len(received) == 2


def test_iter_events(mini_df):
    """Test synchronous generator iter_events with limit."""
    engine = TelemetryReplayEngine(dataframe=mini_df)
    events = list(engine.iter_events(limit=2))

    assert len(events) == 2
    assert engine.current_index == 2


def test_background_worker(mini_df):
    """Test background worker thread emitting events."""
    engine = TelemetryReplayEngine(
        dataframe=mini_df,
        base_interval_sec=0.02,
        speed_multiplier=1.0,
        loop=True,
    )
    received = []
    engine.register_callback(lambda e: received.append(e))

    engine.start_background()
    time.sleep(0.1)  # Let worker run for ~5 ticks
    engine.stop_background()

    assert len(received) >= 2
    assert engine.emitted_count >= 2


def test_async_stream_events(mini_df):
    """Test asynchronous stream generator."""
    async def _runner():
        engine = TelemetryReplayEngine(
            dataframe=mini_df,
            base_interval_sec=0.01,
            speed_multiplier=1.0,
        )
        engine.start()

        streamed = []
        async for evt in engine.stream_events(limit=2):
            streamed.append(evt)

        assert len(streamed) == 2
        assert all(isinstance(e, TelemetryEvent) for e in streamed)

    asyncio.run(_runner())
