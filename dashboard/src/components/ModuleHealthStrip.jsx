/**
 * ModuleHealthStrip — live SSE-driven "Module Health" indicator strip.
 *
 * Subscribes to GET /brain/stream via mlbrainclient.streamModuleEvents().
 * Each incoming event flashes the matching module pill green for 3 seconds,
 * showing the event_type and timestamp as a live confirmation that the module
 * is really talking to ML Brain — visible to the jury without reading logs.
 *
 * Modules tracked: DOWNLINK | UPLINK | FIRMWARE | ACCESS
 */
import { useState, useEffect, useRef } from "react";
import { streamModuleEvents } from "../api/mlbrainclient";

const MODULES = ["DOWNLINK", "UPLINK", "FIRMWARE", "ACCESS"];

const FLASH_DURATION_MS = 3000;

const IDLE_STYLE = {
  background: "rgba(79,209,197,0.08)",
  border: "1px solid rgba(79,209,197,0.2)",
  color: "rgba(200,220,218,0.5)",
  boxShadow: "none",
};

const ACTIVE_STYLE = {
  background: "rgba(79,209,197,0.25)",
  border: "1px solid rgba(79,209,197,0.9)",
  color: "#4FD1C5",
  boxShadow: "0 0 14px rgba(79,209,197,0.5)",
};

function ModuleHealthStrip() {
  // State: per-module { active: bool, label: string, ts: string }
  const [states, setStates] = useState(
    Object.fromEntries(MODULES.map((m) => [m, { active: false, label: "", ts: "" }]))
  );
  // Store timer refs to clear on new events
  const timers = useRef({});

  useEffect(() => {
    const es = streamModuleEvents((msg) => {
      const src = (msg.source || "").toUpperCase();
      if (!MODULES.includes(src)) return;

      // Flash the pill
      setStates((prev) => ({
        ...prev,
        [src]: {
          active: true,
          label: (msg.event_type || "").replace(/_/g, " "),
          ts: msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString("en-US", { hour12: false }) : "",
        },
      }));

      // Clear existing timer for this module
      if (timers.current[src]) clearTimeout(timers.current[src]);

      // Reset to idle after FLASH_DURATION_MS
      timers.current[src] = setTimeout(() => {
        setStates((prev) => ({
          ...prev,
          [src]: { active: false, label: "", ts: "" },
        }));
      }, FLASH_DURATION_MS);
    });

    return () => {
      es.close();
      Object.values(timers.current).forEach(clearTimeout);
    };
  }, []);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        padding: "8px 24px",
        borderBottom: "1px solid rgba(79,209,197,0.12)",
        background: "rgba(10,14,20,0.6)",
        backdropFilter: "blur(8px)",
      }}
    >
      <span
        style={{
          fontSize: "10px",
          letterSpacing: "0.15em",
          color: "rgba(200,220,218,0.4)",
          fontFamily: "monospace",
          whiteSpace: "nowrap",
          marginRight: "4px",
        }}
      >
        MODULE HEALTH
      </span>

      {MODULES.map((mod) => {
        const s = states[mod];
        const style = s.active ? ACTIVE_STYLE : IDLE_STYLE;
        return (
          <div
            key={mod}
            id={`module-health-pill-${mod.toLowerCase()}`}
            style={{
              ...style,
              borderRadius: "4px",
              padding: "4px 10px",
              display: "flex",
              flexDirection: "column",
              alignItems: "flex-start",
              minWidth: "110px",
              transition: "all 0.25s ease",
              cursor: "default",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                fontSize: "10px",
                fontFamily: "monospace",
                letterSpacing: "0.1em",
                fontWeight: s.active ? "700" : "400",
              }}
            >
              <span
                style={{
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: s.active ? "#4FD1C5" : "rgba(79,209,197,0.25)",
                  boxShadow: s.active ? "0 0 6px #4FD1C5" : "none",
                  transition: "all 0.25s ease",
                  flexShrink: 0,
                }}
              />
              {mod}
            </div>
            {s.active && (
              <div
                style={{
                  fontSize: "8px",
                  fontFamily: "monospace",
                  color: "rgba(79,209,197,0.8)",
                  marginTop: "2px",
                  letterSpacing: "0.05em",
                  maxWidth: "100px",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {s.label} {s.ts && `· ${s.ts}`}
              </div>
            )}
          </div>
        );
      })}

      <span
        style={{
          fontSize: "9px",
          fontFamily: "monospace",
          color: "rgba(200,220,218,0.25)",
          marginLeft: "auto",
        }}
      >
        LIVE · /brain/stream
      </span>
    </div>
  );
}

export default ModuleHealthStrip;
