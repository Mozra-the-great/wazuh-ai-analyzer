import { describe, expect, it } from 'vitest';
import { closureOf, inspectPage, sha256Source, type Bundle } from './vite-csp.ts';

describe('inspectPage', () => {
  const clean = '<html><head><script>var a=1</script><script type="module" src="/assets/a.js"></script></head></html>';

  it('accepts one inline script and local references', () => {
    const check = inspectPage('x.html', clean);
    expect(check.inlineScripts).toEqual(['var a=1']);
    expect(check.problems).toEqual([]);
  });

  it.each([
    ['a style element', '<style>a{}</style>'],
    ['a style attribute', '<div style="color:red"></div>'],
    ['an event handler', '<img onerror="x()">'],
    ['a javascript: URL', '<a href="/x" data-x="javascript:1"></a>'],
    ['a foreign reference', '<script src="https://cdn.example/x.js"></script>'],
    ['a protocol-relative reference', '<link href="//cdn.example/x.css">'],
  ])('reports %s', (_name, html) => {
    expect(inspectPage('x.html', html).problems.length).toBeGreaterThan(0);
  });
});

describe('closureOf', () => {
  const files: Record<string, string> = {
    'login.html':
      '<script type="module" src="/assets/login.js"></script><link rel="modulepreload" href="/assets/shared.js"><link rel="stylesheet" href="/assets/shared.css">',
    'assets/shared.css': '@font-face{src:url(./font.woff2)} .a{background:url("../img/x.png")}',
  };
  const bundle: Bundle = {
    'assets/login.js': { type: 'chunk', imports: ['assets/shared.js'], dynamicImports: [] },
    'assets/shared.js': { type: 'chunk', imports: [], dynamicImports: ['assets/lazy.js'] },
    'assets/lazy.js': { type: 'chunk', imports: [], dynamicImports: [] },
  };
  const read = (file: string): string => files[file] ?? '';

  it('follows script imports, modulepreload links and CSS url()s', () => {
    expect(closureOf('login.html', read, bundle)).toEqual([
      'assets/font.woff2',
      'assets/lazy.js',
      'assets/login.js',
      'assets/shared.css',
      'assets/shared.js',
      'img/x.png',
      'login.html',
    ]);
  });

  it('refuses data: and foreign URLs in CSS', () => {
    const withCss =
      (css: string) =>
      (file: string): string =>
        file === 'assets/a.css' ? css : '<link rel="stylesheet" href="/assets/a.css">';
    expect(() => closureOf('p.html', withCss('a{src:url(data:font/woff2;base64,AAAA)}'), {})).toThrow(/data:/);
    expect(() => closureOf('p.html', withCss('a{src:url(https://x.example/f.woff2)}'), {})).toThrow(/foreign/);
  });
});

describe('sha256Source', () => {
  it('matches the format the backend expects', () => {
    expect(sha256Source('abc')).toMatch(/^sha256-[A-Za-z0-9+/]{43}=$/);
  });
});
