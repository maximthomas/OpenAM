import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';

const isProd = process.env.NODE_ENV === 'production';

export default defineConfig({
  root: resolve(__dirname, 'src/main/vue'),
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src/main/vue'),
    },
  },
  css: {
    preprocessorOptions: {
      less: {},
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/openam': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  build: isProd
    ? {
        lib: {
          entry: resolve(__dirname, 'src/main/vue/device-main.ts'),
          formats: ['umd'],
          name: 'OpenAMDevice',
          fileName: () => 'main-device.js',
        },
        outDir: resolve(__dirname, 'target/compiled-vite'),
        emptyOutDir: true,
        rollupOptions: {
          output: {
            assetFileNames: 'assets/[name][extname]',
          },
        },
        cssCodeSplit: false,
        sourcemap: false,
        minify: true,
      }
    : {
        outDir: resolve(__dirname, 'target/compiled-vite'),
        emptyOutDir: true,
        manifest: false,
        rollupOptions: {
          input: resolve(__dirname, 'src/main/vue/index.html'),
          output: {
            entryFileNames: 'assets/[name]-[hash].js',
            chunkFileNames: 'assets/[name]-[hash].js',
            assetFileNames: 'assets/[name]-[hash].[ext]',
          },
        },
      },
  test: {
    environment: 'happy-dom',
    globals: true,
    include: ['src/test/vue/**/*.test.ts'],
  },
});
