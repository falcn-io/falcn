import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    host: true,
    port: 4173,
    strictPort: true,
    proxy: {
      '/v1':      { target: 'http://localhost:8080', changeOrigin: true },
      '/health':  { target: 'http://localhost:8080', changeOrigin: true },
      '/ready':   { target: 'http://localhost:8080', changeOrigin: true },
      '/metrics': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
});
