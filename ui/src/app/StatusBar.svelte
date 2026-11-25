<script lang="ts">
  import { Badge, Button, RelativeTime, StatusDot } from '@mozra-the-great/kern';
  import { epochMs } from '../lib/format.ts';
  import { T } from '../lib/strings.ts';
  import type { Stats } from '../lib/types.ts';

  interface Props {
    stats: Stats | null;
    refreshing: boolean;
    onreload: () => void;
  }
  let { stats, refreshing, onreload }: Props = $props();

  const gemini = $derived.by((): { status: 'ok' | 'warn' | 'down' | 'idle'; label: string } => {
    if (stats === null) return { status: 'idle', label: T.status.gemini };
    if (!stats.geminiOk) return { status: 'down', label: T.status.noKey };
    if (stats.quota.exhausted) return { status: 'warn', label: T.status.quotaEmpty };
    return { status: 'ok', label: T.status.ok };
  });
  const last = $derived(stats === null ? null : epochMs(stats.lastAnalysis));
</script>

<section class="bar" aria-label={T.status.label}>
  <StatusDot status={gemini.status} label={gemini.label} />
  {#if stats !== null}
    <span title={T.status.bufferedTitle}><Badge tone="neutral">{T.status.buffered(stats.bufferedAlerts)}</Badge></span>
    {#if stats.retryQueueSize > 0}
      <span title={T.status.queuedTitle}><Badge tone="warn">{T.status.queued(stats.retryQueueSize)}</Badge></span>
    {/if}
    <span class="last muted">
      {#if last !== null}
        {T.status.lastAnalysis}: <RelativeTime value={last} />
      {:else}
        {T.status.none}
      {/if}
    </span>
  {/if}
  <span class="reload">
    <Button variant="secondary" size="sm" loading={refreshing} onclick={onreload}>{T.actions.reload}</Button>
  </span>
</section>

<style>
  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--k-space-2) var(--k-space-4);
  }
  .last {
    font-size: var(--k-text-sm);
  }
  .reload {
    margin-inline-start: auto;
  }
</style>
