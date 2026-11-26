// Build step for the strict Content-Security-Policy of the backend (docs/web.md).
//
//  1. Every HTML page gets kern's before-paint theme script as its only inline script.
//  2. After the bundle is written, the plugin re-reads the pages, checks that nothing but that
//     script is inline (no other <script>, no <style>, no style="" and no on*="" attribute),
//     hashes the script text exactly as it stands in the page, and
//  3. writes `ui-manifest.json` next to the pages: the hash (for `build_csp(script_hashes=...)`)
//     and the files the login and logout pages need, which the server serves without a session.
//
// The Python side validates the manifest again (wazuh_ai_analyzer/web/ui_manifest.py).
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Plugin } from 'vite';
// kern exposes no Node entry (its package root is a Svelte one), but this helper is plain ESM
// with no imports. The version is pinned by the lockfile, and `src/lib/theme-hash.test.ts`
// checks that the build and kern's public `themeScriptHash` agree.
import { createThemeScript } from '../node_modules/@mozra-the-great/kern/dist/components/theme.js';
import { THEME_KEY } from '../src/lib/theme.ts';

export const MANIFEST_NAME = 'ui-manifest.json';
export const MANIFEST_VERSION = 1;
/** Pages the server serves without a session (PUBLIC_FILES in web/app.py + the manifest). */
export const PUBLIC_PAGES = ['login.html', 'logout.html'] as const;

/** The part of Rolldown's output bundle this plugin reads. */
export type Bundle = Record<
  string,
  {
    type: string;
    imports?: string[];
    dynamicImports?: string[];
    viteMetadata?: { importedCss: Set<string>; importedAssets: Set<string> } | undefined;
  }
>;

const INLINE_SCRIPT = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
const REFERENCES = /(?:\bsrc|\bhref)="([^"]+)"/gi;
const CSS_URLS = /url\(\s*["']?([^"')]+)["']?\s*\)/gi;

export function sha256Source(text: string): string {
  return 'sha256-' + createHash('sha256').update(text, 'utf8').digest('base64');
}

export interface PageCheck {
  inlineScripts: string[];
  problems: string[];
}

/** What a page holds inline; `problems` lists everything the CSP would block. */
export function inspectPage(name: string, html: string): PageCheck {
  const problems: string[] = [];
  const inlineScripts: string[] = [];
  for (const match of html.matchAll(INLINE_SCRIPT)) inlineScripts.push(match[1] ?? '');
  if (/<style[\s>]/i.test(html)) problems.push(`${name}: a <style> element`);
  if (/\sstyle\s*=/i.test(html)) problems.push(`${name}: a style attribute`);
  if (/\son[a-z]+\s*=/i.test(html)) problems.push(`${name}: an event-handler attribute`);
  if (/javascript:/i.test(html)) problems.push(`${name}: a javascript: URL`);
  for (const match of html.matchAll(REFERENCES)) {
    const target = match[1] ?? '';
    if (!target.startsWith('/') || target.startsWith('//')) {
      problems.push(`${name}: a reference that is not local (${target})`);
    }
  }
  return { inlineScripts, problems };
}

function localPath(reference: string): string | null {
  if (!reference.startsWith('/') || reference.startsWith('//')) return null;
  const path = reference.split(/[?#]/)[0] ?? '';
  return path.slice(1) || null;
}

function normalise(path: string): string {
  const out: string[] = [];
  for (const part of path.split('/')) {
    if (part === '..') out.pop();
    else if (part !== '.' && part !== '') out.push(part);
  }
  return out.join('/');
}

/** The files a page loads: its own references, the imports of its scripts, the CSS url()s. */
export function closureOf(page: string, readText: (file: string) => string, bundle: Bundle): string[] {
  const seen = new Set<string>([page]);
  const queue: string[] = [];
  const visit = (file: string | null): void => {
    if (file !== null && !seen.has(file)) {
      seen.add(file);
      queue.push(file);
    }
  };
  for (const match of readText(page).matchAll(REFERENCES)) visit(localPath(match[1] ?? ''));
  for (let file = queue.pop(); file !== undefined; file = queue.pop()) {
    const output = bundle[file];
    if (output !== undefined && output.type === 'chunk') {
      for (const imported of [...(output.imports ?? []), ...(output.dynamicImports ?? [])]) visit(imported);
      for (const css of output.viteMetadata?.importedCss ?? []) visit(css);
      for (const asset of output.viteMetadata?.importedAssets ?? []) visit(asset);
    }
    if (file.endsWith('.css')) {
      const dir = file.includes('/') ? file.slice(0, file.lastIndexOf('/') + 1) : '';
      for (const match of readText(file).matchAll(CSS_URLS)) {
        const url = match[1] ?? '';
        if (url.startsWith('data:')) throw new Error(`${file}: a data: URL (the CSP allows none for fonts)`);
        if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('//')) {
          throw new Error(`${file}: a foreign URL (${url})`);
        }
        visit(url.startsWith('/') ? url.slice(1) : normalise(dir + url));
      }
    }
  }
  return [...seen].sort();
}

export function cspPlugin(): Plugin {
  const themeScript = createThemeScript(THEME_KEY);
  let outDir = '';
  return {
    name: 'wai-csp',
    enforce: 'post',
    transformIndexHtml: {
      order: 'pre',
      handler: () => [{ tag: 'script', children: themeScript, injectTo: 'head-prepend' }],
    },
    configResolved(config) {
      outDir = join(config.root, config.build.outDir);
    },
    writeBundle(_options, bundle) {
      const read = (file: string): string => readFileSync(join(outDir, file), 'utf8');
      const pages = Object.keys(bundle).filter((name) => name.endsWith('.html'));
      const problems: string[] = [];
      for (const page of pages) {
        const check = inspectPage(page, read(page));
        problems.push(...check.problems);
        if (check.inlineScripts.length !== 1 || check.inlineScripts[0] !== themeScript) {
          problems.push(`${page}: the only inline script must be kern's theme script`);
        }
      }
      for (const name of PUBLIC_PAGES) if (!pages.includes(name)) problems.push(`${name} is missing`);
      if (problems.length > 0) throw new Error('CSP check failed:\n  ' + problems.join('\n  '));
      const publicFiles = new Set<string>();
      for (const page of PUBLIC_PAGES) {
        for (const file of closureOf(page, read, bundle)) publicFiles.add(file);
      }
      const manifest = {
        version: MANIFEST_VERSION,
        script_hashes: [sha256Source(themeScript)],
        public_files: [...publicFiles].sort(),
      };
      writeFileSync(join(outDir, MANIFEST_NAME), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    },
  };
}
