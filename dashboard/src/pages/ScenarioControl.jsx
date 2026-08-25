import { useState, useEffect } from "react";

const SIMULATOR_URL = "http://127.0.0.1:8000"; // adjust to actual simulator port

const SCENARIO_FIELDS = {
  NORMAL: [],
  TELEMETRY_ANOMALY: [
    { key: "memory_multiplier", label: "Memory Multiplier", type: "number", default: 4.0, step: 0.1 },
    { key: "inject_page_faults", label: "Page Faults", type: "number", default: 128 },
    { key: "corrupt_command_errors", label: "Command Error Count", type: "number", default: 1 },
  ],
  MESSAGE_BURST: [
    { key: "burst_multiplier", label: "Burst Multiplier", type: "number", default: 10.0, step: 0.5 },
    { key: "compressed_interval_sec", label: "Interval (sec)", type: "number", default: 0.005, step: 0.001 },
    { key: "burst_count", label: "Burst Count", type: "number", default: 3 },
  ],
  MESSAGE_REPLAY: [
    { key: "buffer_size", label: "Buffer Size", type: "number", default: 5 },
    { key: "replay_cycles", label: "Replay Cycles", type: "number", default: 3 },
  ],
};

function ScenarioControl() {
  const [scenarioType, setScenarioType] = useState("NORMAL");
  const [fields, setFields] = useState({});
  const [activeStatus, setActiveStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Reset fields to defaults when scenario type changes
  useEffect(() => {
    const defaults = {};
    SCENARIO_FIELDS[scenarioType].forEach((f) => {
      defaults[f.key] = f.default;
    });
    setFields(defaults);
  }, [scenarioType]);

  // Poll current active scenario status
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch(`${SIMULATOR_URL}/scenario/status`);
        if (res.ok) setActiveStatus(await res.json());
      } catch {
        // simulator not reachable — silently ignore for now
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleFieldChange = (key, value) => {
    setFields((prev) => ({ ...prev, [key]: parseFloat(value) }));
  };

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${SIMULATOR_URL}/scenario`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_type: scenarioType, ...fields }),
      });
      if (!res.ok) throw new Error("Failed to set scenario");
      const data = await res.json();
      setActiveStatus(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-void text-mist font-body px-6 py-6">
      <h1 className="font-display text-lg mb-6">SCENARIO CONTROL</h1>

      {/* Active status */}
      <div className="border hairline rounded-sm px-6 py-4 mb-6">
        <div className="text-xs tracking-widest text-mist/60 mb-2">
          ACTIVE SCENARIO
        </div>
        {activeStatus ? (
          <div className="flex items-center gap-6 font-mono text-sm">
            <span className="text-signal">{activeStatus.active_scenario}</span>
            <span className="text-mist/50">
              Frames processed: {activeStatus.frames_processed}
            </span>
            <span className="text-mist/50">
              Frames modified: {activeStatus.frames_modified}
            </span>
          </div>
        ) : (
          <span className="text-mist/30 text-sm font-mono">
            [ simulator not reachable ]
          </span>
        )}
      </div>

      {/* Scenario selector */}
      <div className="border hairline rounded-sm px-6 py-5">
        <div className="text-xs tracking-widest text-mist/60 mb-4">
          TRIGGER SCENARIO
        </div>

        <select
          value={scenarioType}
          onChange={(e) => setScenarioType(e.target.value)}
          className="bg-panel border hairline rounded-sm px-3 py-2 text-sm font-mono text-mist mb-4 w-full"
        >
          {Object.keys(SCENARIO_FIELDS).map((type) => (
            <option key={type} value={type}>
              {type.replace(/_/g, " ")}
            </option>
          ))}
        </select>

        {SCENARIO_FIELDS[scenarioType].length > 0 && (
          <div className="flex flex-col gap-3 mb-4">
            {SCENARIO_FIELDS[scenarioType].map((field) => (
              <div key={field.key} className="flex items-center justify-between">
                <label className="text-xs font-mono text-mist/60">
                  {field.label}
                </label>
                <input
                  type="number"
                  step={field.step || 1}
                  value={fields[field.key] ?? field.default}
                  onChange={(e) => handleFieldChange(field.key, e.target.value)}
                  className="bg-panel border hairline rounded-sm px-3 py-1 text-sm font-mono text-mist w-32 text-right"
                />
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="text-alertRed text-xs font-mono mb-3">{error}</div>
        )}

        <button
          onClick={handleSubmit}
          disabled={loading}
          className="text-xs font-mono tracking-widest text-void bg-signal px-4 py-2 rounded-sm hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          {loading ? "APPLYING..." : "TRIGGER SCENARIO"}
        </button>
      </div>
    </div>
  );
}

export default ScenarioControl;