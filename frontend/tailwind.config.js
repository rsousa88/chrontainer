/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{vue,js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#edf6ff',
          100: '#d7ebff',
          200: '#b2d6ff',
          300: '#7cb8ff',
          400: '#3f8dff',
          500: '#1d6bff',
          600: '#1553e6',
          700: '#1342b6',
          800: '#143d8f',
          900: '#153471',
        },
        surface: {
          50: '#f8fafc',
          100: '#eef2f7',
          200: '#d7e0ea',
          300: '#b1c1d6',
          400: '#7d95b2',
          500: '#5f7894',
          600: '#4b5f76',
          700: '#3d4c5d',
          800: '#2c3542',
          900: '#1d2430',
        },
      },
    },
  },
  plugins: [],
}
