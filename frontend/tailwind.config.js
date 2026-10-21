/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#0a0d14',
        foreground: '#f1f5f9',
        card: '#111726',
        'card-hover': '#161e33',
        border: '#1e293b',
        primary: '#38bdf8',
        secondary: '#64748b',
        accent: '#f43f5e',
      },
    },
  },
  plugins: [],
};
