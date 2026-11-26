<script lang="ts">
  import { Alert, Button, Card } from '@mozra-the-great/kern';
  import { getSession, loginUrl, logout } from '../lib/api.ts';
  import { T } from '../lib/strings.ts';

  let busy = $state(false);
  let error = $state('');

  // Logging out is a POST with the session's CSRF token: a GET link never logs anybody out.
  async function confirm(): Promise<void> {
    busy = true;
    error = '';
    try {
      const session = await getSession();
      if (!session.authenticated) {
        location.replace(loginUrl('/'));
        return;
      }
      await logout(session.csrfToken);
      location.assign(loginUrl('/'));
    } catch {
      error = T.logout.failed;
      busy = false;
    }
  }
</script>

<main class="logout">
  <Card look="raised" as="section" aria-labelledby="logout-title">
    <h1 id="logout-title">{T.logout.question}</h1>
    {#if error !== ''}
      <Alert tone="danger">{error}</Alert>
    {/if}
    <Button block loading={busy} onclick={confirm}>{T.logout.submit}</Button>
  </Card>
</main>

<style>
  .logout {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: var(--k-space-4);
  }
  .logout > :global(*) {
    width: min(22rem, 100%);
    display: grid;
    gap: var(--k-space-4);
  }
  h1 {
    font-size: var(--k-text-md);
    font-weight: var(--k-weight-heading);
    text-align: center;
  }
</style>
