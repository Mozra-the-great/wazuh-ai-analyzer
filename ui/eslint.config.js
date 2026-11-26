import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';

export default defineConfig(
  { ignores: ['node_modules/', 'test-results/', 'playwright-report/', 'e2e/.run/', '../wazuh_ai_analyzer/web/ui/'] },
  js.configs.recommended,
  ...ts.configs.strictTypeChecked,
  ...svelte.configs['flat/recommended'],
  {
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
      parserOptions: {
        projectService: { allowDefaultProject: ['eslint.config.js', 'svelte.config.js'] },
        extraFileExtensions: ['.svelte'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ['**/*.svelte', '**/*.svelte.ts'],
    languageOptions: { parserOptions: { parser: ts.parser } },
  },
  {
    rules: {
      // The security rules of docs/web.md: API text is rendered as text, never as markup.
      'svelte/no-at-html-tags': 'error',
      'no-restricted-properties': [
        'error',
        { property: 'innerHTML', message: 'Never build markup from strings (docs/web.md).' },
        { property: 'outerHTML', message: 'Never build markup from strings (docs/web.md).' },
        { property: 'insertAdjacentHTML', message: 'Never build markup from strings (docs/web.md).' },
      ],
      'no-restricted-syntax': [
        'error',
        { selector: "CallExpression[callee.name='eval']", message: 'No eval (CSP).' },
        { selector: "NewExpression[callee.name='Function']", message: 'No Function constructor (CSP).' },
        {
          selector: "CallExpression[callee.object.name='document'][callee.property.name='write']",
          message: 'No document.write.',
        },
      ],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-confusing-void-expression': ['error', { ignoreArrowShorthand: true }],
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
    },
  },
  {
    files: ['scripts/**', 'e2e/**', '*.config.ts', 'vite.config.ts'],
    rules: { 'no-restricted-properties': 'off' },
  },
);
