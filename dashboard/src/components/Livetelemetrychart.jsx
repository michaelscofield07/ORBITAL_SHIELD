import { useState, useEffect, useRef } from "react";

const MAX_POINTS = 60;
const UPDATE_INTERVAL_MS = 100; // Faster interval for smoother horizontal flow
const WIDTH = 1000;
const HEIGHT = 160;

// Hardcode Y-axis bounds so the graph doesn't jump vertically when min/max changes
const Y_MIN = 20; 
const Y_MAX = 30;
const Y_RANGE = Y_MAX - Y_MIN;

function LiveTelemetryChart() {
  const [data, setData] = useState([]);
  const timeCounter = useRef(0);

  useEffect(() => {
    let isActive = true;

    const interval = setInterval(() => {
      if (!isActive) return;
      timeCounter.current += 1;
      
      // Adjusted sine wave for the faster interval (divided by 20 instead of 4)
      const nextValue =
        25 + Math.sin(timeCounter.current / 20) * 3 + (Math.random() - 0.5) * 1.5;

      setData((prev) => {
        const updated = [...prev, nextValue];
        return updated.length > MAX_POINTS ? updated.slice(-MAX_POINTS) : updated;
      });
    }, UPDATE_INTERVAL_MS);

    return () => {
      isActive = false;
      clearInterval(interval);
    };
  }, []);

  if (data.length < 2) {
    return <div style={{ height: HEIGHT }} />;
  }

  const points = data
    .map((value, i) => {
      const x = (i / (MAX_POINTS - 1)) * WIDTH;
      // Clamp values so they don't draw outside the SVG if they spike
      const clampedValue = Math.max(Y_MIN, Math.min(Y_MAX, value));
      const y = HEIGHT - ((clampedValue - Y_MIN) / Y_RANGE) * HEIGHT;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        width="100%"
        height={HEIGHT}
        preserveAspectRatio="none"
        className="drop-shadow-[0_0_8px_rgba(79,209,197,0.5)]"
      >
      <polyline
        points={points}
        fill="none"
        stroke="#4FD1C5"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
    
    {/* Subtle gradient overlay at the bottom to give it depth */}
    <div className="absolute bottom-0 left-0 right-0 h-16 bg-gradient-to-t from-signal/5 to-transparent pointer-events-none" />
    </div>
  );
}

export default LiveTelemetryChart;