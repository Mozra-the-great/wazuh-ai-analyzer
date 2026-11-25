<script lang="ts">
  import { Alert, Badge, Progress } from '@mozra-the-great/kern';
  import { clip, formatDuration, formatTime, secondsUntil } from '../lib/format.ts';
  import { T } from '../lib/strings.ts';
  import type { Quota } from '../lib/types.ts';

  interface Props {
    quota: Quota;
    queueSize: number;
  }
  let { quota, queueSize }: Props = $props();

  let now = $state(Date.now());
  $effect(() => {
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

  const remaining = $derived(secondsUntil(quota.retryAt, now));
  // The bar counts down from the wait seen when this retry time first appeared.
  let seenAt = '';
  let seenTotal = 1;
  const total = $derived.by(() => {
    const at = quota.retryAt ?? '';
    if (at !== seenAt) {
      seenAt = at;
      seenTotal = Math.max(1, secondsUntil(quota.retryAt, Date.now()) ?? quota.retryInSeconds);
    }
    return seenTotal;
  });
  const countdown = $derived(remaining === null ? '–' : formatDuration(remaining));
</script>

<Alert tone="warn" title={T.quota.title}>
  <div class="body wrap">
    <p>{quota.lastError === '' ? T.quota.body : T.quota.bodyWithError(clip(quota.lastError, 200))}</p>
    <dl class="meta">
      <div>
        <dt>{T.quota.since}</dt>
        <dd>{formatTime(quota.exhaustedSince)}</dd>
      </div>
      <div>
        <dt>{T.quota.next}</dt>
        <!-- aria-live off: the ticking text must not be read out every second -->
        <dd aria-live="off">{countdown}</dd>
      </div>
      {#if quota.retryCount > 1}
        <div>
          <dt>{T.quota.attempts}</dt>
          <dd>{quota.retryCount}</dd>
        </div>
      {/if}
      <div>
        <dt>{T.quota.queue}</dt>
        <dd>{T.quota.queueUnit(queueSize)}</dd>
      </div>
    </dl>
    {#if remaining !== null}
      <Progress
        label={T.quota.progress}
        hideLabel
        tone="warn"
        value={Math.min(remaining, total)}
        max={total}
        valueText={countdown}
      />
    {/if}
    <Badge tone="warn" look="outline">{T.quota.paused}</Badge>
  </div>
</Alert>

<style>
  .body {
    display: grid;
    gap: var(--k-space-3);
  }
  .body :global(.k-badge) {
    justify-self: start;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: var(--k-space-2) var(--k-space-6);
    margin: 0;
    font-size: var(--k-text-sm);
  }
  .meta dt {
    color: var(--k-fg-muted);
    font-size: var(--k-text-xs);
  }
  .meta dd {
    margin: 0;
    font-weight: var(--k-weight-heading);
    font-variant-numeric: tabular-nums;
  }
</style>
