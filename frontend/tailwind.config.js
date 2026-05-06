/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        slatebg: {
          950: "#030712",
          900: "#0b1220",
          800: "#111827",
        },
        emeraldsafe: "#10b981",
        rubyrisk: "#f43f5e",
      },
      boxShadow: {
        glass: "0 10px 35px rgba(2, 6, 23, 0.35)",
      },
      backdropBlur: {
        xs: "2px",
      },
    },
  },
  plugins: [],
};
