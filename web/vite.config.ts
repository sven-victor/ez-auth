import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

function toSnakeCase(str: string) {
  return str.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

// https://vitejs.dev/config/
export default defineConfig({
  base: '/ui/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/console': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
    allowedHosts: ['idas.microops.com'],
    host: '0.0.0.0',
  },
  build: {
    sourcemap: true,
    outDir: 'dist',
  },
  css: {
    preprocessorOptions: {
      less: {
        javascriptEnabled: true,
      },
    },
  },
}) 