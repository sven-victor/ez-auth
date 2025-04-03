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
    outDir: 'dist',
    sourcemap: process.env.NODE_ENV !== 'production',
    rollupOptions: {
      treeshake: true,
      output: {
        manualChunks(id, meta) {
          if (id.includes('node_modules')) return 'vendor';
          if (id.includes('/src/main.tsx') || id.includes('/src/App.tsx') || id.includes('/src/components/Layout.tsx') || id.includes('/src/routes/')) return 'index';
          if (id.includes('/src/contexts/') || id.includes('/src/hooks/')) return "contexts";
          if (id.includes('/src/pages/Application/')) return 'applications';
          if (id.includes('/src/pages/OIDC/')) return 'oidc';
          if (id.includes('/src/pages/Settings')) return 'settings';
          if (id.includes('/src/pages/User/')) return 'users';
          if (id.includes('/src/i18n/') || id.includes('/src/utils/') || id.includes('/src/constants/') || id.includes('/src/types/') || id.includes('/src/api/')) return 'base';
          if (id.includes('/src/components/')) return 'components';
          if (id.startsWith('\x00vite/') || id === '\x00commonjsHelpers.js') {
            return "vite";
          };
          return toSnakeCase(path.basename(id, path.extname(id)))
        }
      },
    },
  },
  css: {
    preprocessorOptions: {
      less: {
        javascriptEnabled: true,
      },
    },
  },
}) 