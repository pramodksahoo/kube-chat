import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  // Resolve configuration for path aliases
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@/components': path.resolve(__dirname, './src/components'),
      '@/hooks': path.resolve(__dirname, './src/hooks'),
      '@/services': path.resolve(__dirname, './src/services'),
      '@/stores': path.resolve(__dirname, './src/stores'),
      '@/utils': path.resolve(__dirname, './src/utils'),
      '@/types': path.resolve(__dirname, './src/types'),
    },
  },

  // Development server configuration - ALWAYS USE PORT 3001
  server: {
    port: 3001,
    strictPort: true, // Fail if port is already in use instead of auto-incrementing
    host: true, // Allow external connections
    hmr: {
      overlay: true,
    },
    open: false, // Don't auto-open browser (good for CI/CD)
  },

  // Build optimizations
  build: {
    target: 'esnext', // Modern browsers for better performance
    minify: 'esbuild', // Fast minification
    sourcemap: true, // Generate sourcemaps for debugging
    outDir: 'dist',
    assetsDir: 'assets',

    // Chunk splitting for better caching
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
        },
      },
    },

    // Performance optimizations
    chunkSizeWarningLimit: 1000,
    reportCompressedSize: false, // Faster builds
  },

  // Preview configuration
  preview: {
    port: 4173,
    host: true,
  },

  // Optimization configuration
  optimizeDeps: {
    include: ['react', 'react-dom'],
  },
});
