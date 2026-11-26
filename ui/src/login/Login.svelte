<script lang="ts">
  import { Alert, Button, Card, Input } from '@mozra-the-great/kern';
  import { onMount } from 'svelte';
  import { ApiError, getSession, login } from '../lib/api.ts';
  import { T } from '../lib/strings.ts';

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);
  let blocked = $state(false);
  let csrf = '';

  const nextPath = (): string => new URLSearchParams(location.search).get('next') ?? '/';

  // The pre-session token (`GET /api/session`) belongs to a cookie the server sets here.
  async function loadSession(): Promise<void> {
    try {
      const session = await getSession();
      if (session.authenticated) {
        location.replace('/');
        return;
      }
      csrf = session.csrfToken;
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 503) {
        error = T.login.noPassword;
        blocked = true;
      } else {
        error = T.login.unreachable;
      }
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy || blocked) return;
    error = '';
    busy = true;
    try {
      if (csrf === '') await loadSession();
      if (csrf === '') return;
      const result = await login(csrf, username, password, nextPath());
      // `next` was reduced to a local path by the server (and by `login()` again).
      location.assign(result.next);
    } catch (caught) {
      if (!(caught instanceof ApiError)) {
        error = T.login.unreachable;
      } else if (caught.status === 429) {
        const wait = Number(caught.body['retry_after']);
        error = T.login.tooMany(Number.isFinite(wait) && wait > 0 ? Math.ceil(wait) : 60);
      } else if (caught.status === 401) {
        const left = Number(caught.body['remaining_attempts']);
        error = T.login.wrong(Number.isFinite(left) && left > 0 ? left : 0);
        password = '';
      } else if (caught.status === 403) {
        csrf = '';
        await loadSession();
        if (error === '') error = T.login.expired;
      } else {
        error = T.login.failed;
      }
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    document.getElementById('username')?.focus();
    void loadSession();
  });
</script>

<main class="login">
  <Card look="raised" as="section" aria-labelledby="login-title">
    <header class="brand">
      <h1 id="login-title">{T.appName}</h1>
      <p class="muted">{T.appSub}</p>
    </header>
    <form onsubmit={submit} class="form" aria-label={T.login.title}>
      <Input
        id="username"
        name="username"
        label={T.login.username}
        autocomplete="username"
        autocapitalize="none"
        spellcheck={false}
        required
        bind:value={username}
      />
      <Input
        id="password"
        name="password"
        type="password"
        label={T.login.password}
        autocomplete="current-password"
        required
        bind:value={password}
      />
      {#if error !== ''}
        <Alert tone="danger">{error}</Alert>
      {/if}
      <Button type="submit" block loading={busy} disabled={blocked}>{T.login.submit}</Button>
    </form>
    <p class="footer muted">{T.login.footer}</p>
  </Card>
</main>

<style>
  .login {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: var(--k-space-4);
  }
  .login :global(.k-card),
  .login > :global(*) {
    width: min(26rem, 100%);
  }
  .brand {
    text-align: center;
  }
  .brand h1 {
    font-family: var(--k-font-display);
    font-size: var(--k-text-lg);
    font-weight: var(--k-weight-display);
  }
  .brand p {
    font-size: var(--k-text-xs);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .form {
    display: grid;
    gap: var(--k-space-4);
    margin-top: var(--k-space-4);
  }
  .footer {
    margin-top: var(--k-space-5);
    font-size: var(--k-text-xs);
    text-align: center;
  }
</style>
