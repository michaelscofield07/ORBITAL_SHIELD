export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        void: "#0B0E14",
        panel: "#131822",
        signal: "#4FD1C5",
        warnAmber: "#E8A33D",
        alertRed: "#E8544B",
        mist: "#B8C4D9",
      },
      fontFamily: {
        display: ["Space Grotesk", "sans-serif"],
        body: ["IBM Plex Sans", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
