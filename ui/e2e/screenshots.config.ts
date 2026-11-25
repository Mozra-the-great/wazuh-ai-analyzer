import { defineConfig } from '@playwright/test';
import base from '../playwright.config.ts';

// `npm run screenshots`: the screenshot set for the PR (desktop and mobile, light and dark).
export default defineConfig({
  ...base,
  testDir: '.',
  testMatch: /.*\.shots\.ts/,
  timeout: 60_000,
});
