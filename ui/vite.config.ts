import { fileURLToPath } from 'node:url';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';
import { cspPlugin } from './scripts/vite-csp.ts';

const root = fileURLToPath(new URL('.', import.meta.url));
const page = (name: string): string => fileURLToPath(new URL(`./${name}`, import.meta.url));

// A plain Vite SPA (not SvelteKit): the only variant of kern's Svelte path that is tested under a
// strict CSP. The output goes straight into the Python package (`UI_DIR` in service.py).
export default defineConfig({
  root,
  base: '/',
  plugins: [svelte(), cspPlugin()],
  build: {
    outDir: '../wazuh_ai_analyzer/web/ui',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    // No data: URIs: the CSP allows none for fonts, and the server is happy to serve files.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    cssCodeSplit: true,
    rolldownOptions: {
      input: { index: page('index.html'), login: page('login.html'), logout: page('logout.html') },
    },
  },
});
