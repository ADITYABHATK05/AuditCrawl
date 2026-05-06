/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        sea: {
          950: '#020617',
          900: '#0b1120',
          850: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
        },
        neon: {
          DEFAULT: '#00e5a0',
          50:  'rgba(0,229,160,0.05)',
          100: 'rgba(0,229,160,0.10)',
          200: 'rgba(0,229,160,0.20)',
          400: '#34d399',
          500: '#00e5a0',
          600: '#059669',
        },
        crimson: {
          DEFAULT: '#ff3355',
          50:  'rgba(255,51,85,0.05)',
          100: 'rgba(255,51,85,0.10)',
          200: 'rgba(255,51,85,0.20)',
          400: '#fb7185',
          500: '#ff3355',
        },
        sev: {
          critical: '#ff3355',
          high:     '#ff8c00',
          medium:   '#ffd700',
          low:      '#40aaff',
          info:     '#64748b',
        },
      },
      boxShadow: {
        glass:  '0 10px 35px rgba(2,6,23,0.35)',
        glow:   '0 0 20px rgba(0,229,160,0.15)',
        danger: '0 0 20px rgba(255,51,85,0.15)',
      },
      backdropBlur: { xs: '2px' },
      fontFamily: {
        mono:    ['"Share Tech Mono"', 'monospace'],
        display: ['"Syne"', 'sans-serif'],
      },
      animation: {
        'scan-pulse': 'scanPulse 2s cubic-bezier(0.4,0,0.6,1) infinite',
        'shimmer':    'shimmer 2s linear infinite',
        'glow-ring':  'glowRing 2.5s ease-in-out infinite',
      },
      keyframes: {
        scanPulse: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(0,229,160,0.4)' },
          '50%':      { boxShadow: '0 0 0 12px rgba(0,229,160,0)' },
        },
        shimmer: {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        glowRing: {
          '0%, 100%': { opacity: '0.4', transform: 'scale(1)' },
          '50%':      { opacity: '1', transform: 'scale(1.15)' },
        },
      },
    },
  },
  plugins: [],
};
