import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Plain CSS files, no inline <style> at run time: the page runs under `style-src 'self'`.
    css: 'external',
  },
};
