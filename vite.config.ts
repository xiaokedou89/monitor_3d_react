/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    port: 5178,
    host: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:9528', changeOrigin: true },
      '/healthz': { target: 'http://127.0.0.1:9528', changeOrigin: true },
      '/readyz': { target: 'http://127.0.0.1:9528', changeOrigin: true },
    },
  },
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 1600,
    rollupOptions: {
      output: {
        manualChunks: (id: string) => (id.includes('node_modules/three') ? 'three' : undefined),
      },
    },
  },
  test: {
    include: ['test/unit/**/*.test.ts'],
    environment: 'node',
  },
});
