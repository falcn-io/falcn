/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          0:  '#05060e',
          1:  '#0d1117',
          2:  '#111827',
          3:  '#161f30',
          4:  '#1e2a40',
          5:  '#253248',
        },
        accent: {
          DEFAULT: '#6366f1',
          hover:   '#818cf8',
          dim:     'rgba(99,102,241,0.15)',
          ghost:   'rgba(99,102,241,0.07)',
        },
        teal: {
          DEFAULT: '#14b8a6',
          hover:   '#2dd4bf',
          dim:     'rgba(20,184,166,0.15)',
        },
        sev: {
          critical: '#f43f5e',
          high:     '#f97316',
          medium:   '#f59e0b',
          low:      '#22c55e',
          none:     '#64748b',
          'critical-bg': 'rgba(244,63,94,0.12)',
          'high-bg':     'rgba(249,115,22,0.12)',
          'medium-bg':   'rgba(245,158,11,0.12)',
          'low-bg':      'rgba(34,197,94,0.12)',
        },
        border: {
          DEFAULT: '#1e2a40',
          bright:  '#2d3d5a',
          glow:    'rgba(99,102,241,0.3)',
        },
        ink: {
          DEFAULT: '#e2e8f0',
          muted:   '#94a3b8',
          faint:   '#475569',
        },
      },
      fontFamily: {
        sans: ['Inter var', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.65rem', { lineHeight: '1rem' }],
      },
      boxShadow: {
        card:          '0 1px 3px rgba(0,0,0,0.5), 0 1px 2px rgba(0,0,0,0.7)',
        'card-hover':  '0 8px 24px rgba(0,0,0,0.6)',
        'glow-accent': '0 0 24px rgba(99,102,241,0.3)',
        'glow-teal':   '0 0 24px rgba(20,184,166,0.25)',
        'glow-red':    '0 0 24px rgba(244,63,94,0.25)',
        inner:         'inset 0 1px 0 rgba(255,255,255,0.04)',
      },
      borderRadius: {
        xl2: '1rem',
        xl3: '1.25rem',
      },
      animation: {
        'fade-in':    'fadeIn 0.25s ease-out',
        'slide-up':   'slideUp 0.3s ease-out',
        'slide-in-r': 'slideInRight 0.3s ease-out',
        'pulse-dot':  'pulseDot 2s ease-in-out infinite',
        'scan':       'scan 2.5s linear infinite',
      },
      keyframes: {
        fadeIn:       { from: { opacity: '0' },              to: { opacity: '1' } },
        slideUp:      { from: { transform: 'translateY(12px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
        slideInRight: { from: { transform: 'translateX(16px)', opacity: '0' }, to: { transform: 'translateX(0)', opacity: '1' } },
        pulseDot:     { '0%,100%': { opacity: '1', transform: 'scale(1)' }, '50%': { opacity: '0.5', transform: 'scale(0.8)' } },
        scan:         { '0%': { top: '0%' }, '100%': { top: '100%' } },
      },
      backgroundImage: {
        'noise':          "url(\"data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E\")",
        'accent-gradient': 'linear-gradient(135deg, #6366f1 0%, #14b8a6 100%)',
        'card-shine':      'linear-gradient(135deg, rgba(255,255,255,0.04) 0%, transparent 50%)',
      },
    },
  },
  plugins: [require('@tailwindcss/forms')],
};
