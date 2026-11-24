import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const csp = JSON.parse(readFileSync(fileURLToPath(new URL('./csp.json', import.meta.url)), 'utf8'));

function injectCsp(command) {
  return {
    name: 'steadypc-csp',
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        return html.replace('__STEADYPC_CSP__', command === 'serve' ? csp.dev : csp.prod);
      },
    },
  };
}

export default defineConfig(({ command }) => ({
  base: './',
  plugins: [injectCsp(command), react()],
  server: {
    host: '127.0.0.1',
    port: 3000,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
}));
