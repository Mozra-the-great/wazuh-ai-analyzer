<script lang="ts">
  import { Badge, Skeleton, Tag } from '@mozra-the-great/kern';
  import { formatConfidence, formatTime } from '../lib/format.ts';
  import { SOURCE_LABEL, T } from '../lib/strings.ts';
  import type { Finding, FindingDetail } from '../lib/types.ts';
  import SeverityBadge from './SeverityBadge.svelte';

  interface Props {
    finding: Finding;
    /** The full record (batch summary, alert count); null while it loads. */
    detail: FindingDetail | null;
    failed: boolean;
  }
  let { finding, detail, failed }: Props = $props();

  const confidence = $derived(formatConfidence(finding.confidence));
  const mode = $derived(T.detail.mode[finding.mode] ?? finding.mode);
</script>

<!-- Everything from the API below is attacker-influenced text: text nodes only, no markup. -->
<!-- tabindex: the drawer body scrolls, and a scroll region must be reachable by keyboard -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<article class="detail" tabindex="0" aria-labelledby="d-title">
  <h3 id="d-title" class="title wrap">{finding.title}</h3>
  <div class="badges">
    <SeverityBadge severity={finding.severity} />
    <Badge tone="neutral" look="outline">{SOURCE_LABEL[finding.source]}</Badge>
    <Badge tone="neutral" look="outline">{mode}</Badge>
    {#if confidence !== null}
      <Badge tone="neutral" look="outline">{T.detail.confidence}: {confidence}</Badge>
    {/if}
  </div>

  <section aria-labelledby="d-problem">
    <h3 id="d-problem">{T.detail.problem}</h3>
    <p class="wrap text">{finding.description}</p>
  </section>

  <section aria-labelledby="d-rec">
    <h3 id="d-rec">{T.detail.recommendation}</h3>
    <p class="ai"><Badge tone="accent" look="outline">{T.detail.recommendationHint}</Badge></p>
    <p class="wrap text rec">{finding.recommendation}</p>
    <p class="note muted">{T.aiNote}</p>
  </section>

  {#if finding.agents.length > 0}
    <section aria-labelledby="d-agents">
      <h3 id="d-agents">{T.detail.agents}</h3>
      <ul class="tags">
        {#each finding.agents as agent, i (i)}
          <li><Tag>{agent}</Tag></li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if finding.ruleIds.length > 0}
    <section aria-labelledby="d-rules">
      <h3 id="d-rules">{T.detail.rules}</h3>
      <ul class="tags">
        {#each finding.ruleIds as rule, i (i)}
          <li><Tag>{rule}</Tag></li>
        {/each}
      </ul>
    </section>
  {/if}

  <section aria-labelledby="d-batch">
    <h3 id="d-batch">{T.detail.batch}</h3>
    <p class="muted">
      {T.detail.analysed(formatTime(finding.batchTime), finding.batchId)}{finding.source === 'history'
        ? ` · ${T.detail.history}`
        : ''}
    </p>
    {#if detail !== null}
      {#if detail.alertCount !== null}
        <p class="muted">{T.detail.alerts(detail.alertCount)}</p>
      {/if}
      {#if detail.batchSummary !== null}
        <h4>{T.detail.batchSummary}</h4>
        <p class="ai"><Badge tone="accent" look="outline">{T.aiGenerated}</Badge></p>
        <p class="wrap text">{detail.batchSummary}</p>
      {/if}
    {:else if failed}
      <p class="muted" role="status">{T.detail.summaryFailed}</p>
    {:else}
      <div role="status" aria-label={T.detail.summaryLoading}>
        <Skeleton lines={2} />
      </div>
    {/if}
  </section>
</article>

<style>
  .detail {
    display: grid;
    gap: var(--k-space-5);
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: var(--k-space-2);
  }
  .title {
    font-size: var(--k-text-md);
    font-weight: var(--k-weight-heading);
  }
  h3:not(.title) {
    margin-bottom: var(--k-space-2);
    color: var(--k-fg-muted);
    font-family: var(--k-label-font);
    font-size: var(--k-text-xs);
    font-weight: var(--k-weight-label);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  h4 {
    margin: var(--k-space-3) 0 var(--k-space-2);
    font-size: var(--k-text-sm);
    font-weight: var(--k-weight-heading);
  }
  .text {
    white-space: pre-line;
  }
  .rec {
    padding: var(--k-space-3);
    border-inline-start: 3px solid var(--k-accent-text);
    background: var(--k-bg-sunken);
    border-radius: var(--k-radius-control);
  }
  .ai {
    margin-bottom: var(--k-space-2);
  }
  .note {
    margin-top: var(--k-space-2);
    font-size: var(--k-text-xs);
  }
  .tags {
    /* host names and rule ids are shown exactly as they are */
    --k-label-transform: none;
    display: flex;
    flex-wrap: wrap;
    gap: var(--k-space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  .tags li {
    min-width: 0;
    overflow-wrap: anywhere;
  }
</style>
