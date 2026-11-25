<script lang="ts">
  import { Badge, Card } from '@mozra-the-great/kern';
  import { T } from '../lib/strings.ts';
  import type { BatchSummary } from '../lib/types.ts';
  import SeverityBadge from './SeverityBadge.svelte';

  interface Props {
    summary: BatchSummary;
  }
  let { summary }: Props = $props();
</script>

<!-- The summary was written by a model: shown as text, labelled as AI generated and unverified. -->
<section aria-label={T.summary.title}>
<Card as="div" level={2} title={T.summary.title} look="outline">
  {#snippet badges()}
    <Badge tone="accent" look="outline">{T.aiGenerated}</Badge>
  {/snippet}
  <div class="content">
    {#if summary.overallRisk !== null}
      <p class="risk">
        <span class="muted">{T.summary.risk}:</span>
        <SeverityBadge severity={summary.overallRisk} />
      </p>
    {/if}
    <p class="text wrap">{summary.summary}</p>
  </div>
</Card>
</section>

<style>
  .content {
    display: grid;
    gap: var(--k-space-2);
  }
  .risk {
    display: flex;
    align-items: center;
    gap: var(--k-space-2);
  }
  .text {
    white-space: pre-line;
  }
</style>
