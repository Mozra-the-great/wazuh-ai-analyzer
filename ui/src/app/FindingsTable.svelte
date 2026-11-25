<script lang="ts">
  import { Badge, Table, type Column } from '@mozra-the-great/kern';
  import { formatTime } from '../lib/format.ts';
  import { SOURCE_LABEL, T } from '../lib/strings.ts';
  import type { Finding, Severity, Source } from '../lib/types.ts';
  import SeverityBadge from './SeverityBadge.svelte';

  interface Props {
    findings: Finding[];
    onopen: (finding: Finding) => void;
  }
  let { findings, onopen }: Props = $props();

  // A type alias (not an interface): kern's Table wants `Record<string, unknown>` rows.
  type Row = {
    severity: Severity;
    title: string;
    time: string;
    source: Source;
    agents: string;
    rules: string;
    index: number;
  };

  const columns: Column<Row>[] = [
    { key: 'severity', label: T.list.columns.severity },
    { key: 'title', label: T.list.columns.title },
    { key: 'time', label: T.list.columns.time },
    { key: 'source', label: T.list.columns.source },
    { key: 'agents', label: T.list.columns.agents },
    { key: 'rules', label: T.list.columns.rules },
  ];

  const rows = $derived<Row[]>(
    findings.map((finding, index) => ({
      severity: finding.severity,
      title: finding.title,
      time: formatTime(finding.batchTime),
      source: finding.source,
      agents: finding.agents.join(', '),
      rules: finding.ruleIds.join(', '),
      index,
    })),
  );

  function open(row: Row): void {
    const finding = findings[row.index];
    if (finding !== undefined) onopen(finding);
  }
</script>

<!-- Every text below comes from the API: it is rendered as a text node, never as markup. -->
<Table {columns} {rows} caption={T.list.caption} captionHidden empty={T.list.emptyFiltered}>
  {#snippet cell({ row, column })}
    {#if column.key === 'severity'}
      <SeverityBadge severity={row.severity} />
    {:else if column.key === 'title'}
      <button type="button" class="open wrap" aria-label={T.list.open(row.title)} onclick={() => open(row)}>
        {row.title}
      </button>
    {:else if column.key === 'source'}
      <Badge tone="neutral" look="outline">{SOURCE_LABEL[row.source]}</Badge>
    {:else if column.key === 'agents' || column.key === 'rules'}
      <span class="wrap">{row[column.key] === '' ? '–' : row[column.key]}</span>
    {:else}
      {row[column.key]}
    {/if}
  {/snippet}
</Table>

<style>
  .open {
    display: inline;
    padding: var(--k-space-1) 0;
    border: 0;
    background: none;
    color: var(--k-link);
    font: inherit;
    font-weight: var(--k-weight-heading);
    text-align: start;
    text-decoration: underline;
    text-underline-offset: 0.2em;
    cursor: pointer;
    min-height: var(--k-tap-min);
  }
  .open:hover {
    text-decoration-thickness: 2px;
  }
  .open:focus-visible {
    outline: var(--k-focus-w) solid var(--k-focus);
    outline-offset: var(--k-focus-offset);
    border-radius: var(--k-radius-control);
  }
</style>
