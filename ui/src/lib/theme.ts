// Theme settings shared by the app and by the build (the build derives the CSP hash of the
// before-paint theme script from the same values, see scripts/vite-csp.ts).

/** localStorage key of the chosen theme; the ThemeToggle's `persist` and the script use it. */
export const THEME_KEY = 'wai-theme';

export interface ThemeChoice {
  id: string;
  label: string;
}

/** Light first. The dark theme is the default (decision D4), set as `data-theme` in the pages. */
export const THEMES: readonly [ThemeChoice, ThemeChoice] = [
  { id: 'code-light', label: 'Hell' },
  { id: 'code', label: 'Dunkel' },
];
