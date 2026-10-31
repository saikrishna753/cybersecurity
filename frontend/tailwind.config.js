/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // SOC-inspired dark navy palette
        navy: {
          950: '#070c18',
          900: '#0a1122',
          850: '#0d1529',
          800: '#111b33',
          700: '#1a2744',
          600: '#243457',
        },
        accent: { DEFAULT: '#3b82f6', soft: '#60a5fa', dim: '#1d4ed8' },
        status: {
          normal: '#22c55e',
          warn: '#f59e0b',
          crit: '#ef4444',
          info: '#38bdf8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'fade-in': 'fadeIn 0.2s ease-out',
      },
      keyframes: {
        fadeIn: { from: { opacity: '0', transform: 'translateY(4px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
      },
    },
  },
  plugins: [],
};
