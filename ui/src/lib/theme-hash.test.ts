import { createThemeScript, themeScriptHash } from '@mozra-the-great/kern';
import { describe, expect, it } from 'vitest';
import { cspPlugin, sha256Source } from '../../scripts/vite-csp.ts';
import { THEME_KEY } from './theme.ts';

describe('theme script hash', () => {
  it('the build hashes the same text as the kern export that the docs name', async () => {
    const script = createThemeScript(THEME_KEY);
    // kern's `themeScriptHash` returns the quoted CSP source; the manifest holds it unquoted.
    expect(`'${sha256Source(script)}'`).toBe(await themeScriptHash(THEME_KEY));
  });

  it('the plugin injects exactly that script into every page, first in the head', () => {
    const plugin = cspPlugin();
    const hook = plugin.transformIndexHtml;
    if (hook === undefined || typeof hook === 'function') throw new Error('unexpected hook shape');
    const tags = (hook.handler as (html: string) => { tag: string; children: string; injectTo: string }[])('');
    expect(tags).toEqual([
      { tag: 'script', children: createThemeScript(THEME_KEY), injectTo: 'head-prepend' },
    ]);
  });
});
