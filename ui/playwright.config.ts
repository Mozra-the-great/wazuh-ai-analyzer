import { defineConfig, devices } from '@playwright/test';

// The tests run against the real backend (e2e/server.py: waitress, Flask, the real CSP and
// headers, a fixture database) serving the production build of this app. Build first:
// `npm run build`. Set E2E_PYTHON to the interpreter that has the backend requirements.
const PORT = 8799;

export default defineConfig({
  testDir: './e2e',
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  reporter: process.env['CI'] === undefined ? 'list' : [['list'], ['github']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    ...devices['Desktop Chrome'],
    locale: 'de-DE',
    timezoneId: 'Europe/Berlin',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `${process.env['E2E_PYTHON'] ?? 'python'} e2e/server.py --port ${PORT} --run-dir e2e/.run`,
    url: `http://127.0.0.1:${PORT}/login`,
    cwd: import.meta.dirname,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 },
  },
});
