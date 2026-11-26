<script lang="ts">
  import {
    Button,
    Drawer,
    EmptyState,
    LiveAnnouncer,
    Navbar,
    Pagination,
    SegmentedControl,
    Skeleton,
    SkipLink,
    ThemeToggle,
    Toaster,
    type SegmentOption,
  } from '@mozra-the-great/kern';
  import { onMount } from 'svelte';
  import { SEVERITY_LABEL, SOURCE_LABEL, T } from '../lib/strings.ts';
  import { THEME_KEY, THEMES } from '../lib/theme.ts';
  import { SEVERITIES, type Finding, type Severity, type Source } from '../lib/types.ts';
  import { Dashboard } from './dashboard.svelte.ts';
  import FindingDetail from './FindingDetail.svelte';
  import FindingsTable from './FindingsTable.svelte';
  import HistoryBanner from './HistoryBanner.svelte';
  import QuotaBanner from './QuotaBanner.svelte';
  import SeverityTiles from './SeverityTiles.svelte';
  import StatusBar from './StatusBar.svelte';
  import SummaryBanner from './SummaryBanner.svelte';

  const dash = new Dashboard();

  const severityOptions: SegmentOption[] = [
    { value: '', label: T.list.all },
    ...SEVERITIES.map((level) => ({ value: level, label: SEVERITY_LABEL[level] })),
  ];
  const sourceOptions: SegmentOption[] = [
    { value: '', label: T.list.all },
    { value: 'live', label: SOURCE_LABEL.live },
    { value: 'history', label: SOURCE_LABEL.history },
  ];

  const filtered = $derived(dash.severity !== '' || dash.source !== '');
  const pages = $derived(dash.pageCount);

  onMount(() => {
    void dash.start();
    return () => dash.stop();
  });
</script>

<SkipLink target="main" label={T.skipLink} />

<Navbar>
  {#snippet brand()}
    <span class="brand">
      <span class="brand-name">{T.appName}</span>
      <span class="brand-sub muted">{T.appSub}</span>
    </span>
  {/snippet}
  {#snippet actions()}
    <ThemeToggle themes={[...THEMES]} persist={THEME_KEY} label="Dunkelmodus" />
    <Button variant="secondary" size="sm" onclick={() => void dash.logout()}>{T.actions.logout}</Button>
  {/snippet}
</Navbar>

<main id="main" class="page" tabindex="-1">
  <h1 class="sr-only">Security Dashboard</h1>

  <StatusBar stats={dash.stats} refreshing={dash.refreshing} onreload={() => void dash.refresh()} />

  {#if dash.stats !== null && dash.stats.quota.exhausted}
    <QuotaBanner quota={dash.stats.quota} queueSize={dash.stats.retryQueueSize} />
  {/if}
  {#if dash.stats !== null && !dash.stats.history.done}
    <HistoryBanner history={dash.stats.history} />
  {/if}
  {#if dash.summary !== null}
    <SummaryBanner summary={dash.summary} />
  {/if}

  <SeverityTiles stats={dash.stats} />

  <section class="list" aria-labelledby="list-title">
    <div class="list-head">
      <h2 id="list-title">
        {T.list.heading}
        {#if dash.listState === 'ready' && dash.total > 0}
          <span class="count muted">{T.list.count(dash.total)}</span>
        {/if}
      </h2>
      <div class="filters">
        <SegmentedControl
          label={T.tiles.filter}
          options={severityOptions}
          value={dash.severity}
          onchange={(value) => dash.setSeverity(value as Severity | '')}
        />
        <SegmentedControl
          label={T.list.sourceLabel}
          options={sourceOptions}
          value={dash.source}
          onchange={(value) => dash.setSource(value as Source | '')}
        />
      </div>
    </div>

    {#if dash.listState === 'loading'}
      <div class="skeleton" role="status" aria-busy="true" aria-label={T.list.loading}>
        {#each [0, 1, 2, 3] as row (row)}
          <Skeleton variant="rect" height={56} />
        {/each}
      </div>
    {:else if dash.listState === 'error'}
      <EmptyState title={T.list.errorTitle} description={T.list.errorBody}>
        {#snippet actions()}
          <div class="empty-actions">
            <p class="mono hint">systemctl status wazuh-ai-analyzer<br />journalctl -u wazuh-ai-analyzer -f</p>
            <Button variant="secondary" onclick={() => void dash.refresh()}>{T.list.retry}</Button>
          </div>
        {/snippet}
      </EmptyState>
    {:else if dash.total === 0 && !filtered}
      <EmptyState title={T.list.emptyTitle} description={T.list.emptyBody} />
    {:else}
      <FindingsTable findings={dash.findings} onopen={(finding: Finding) => {
          dash.open(finding);
        }} />
      {#if pages > 1}
        <Pagination
          page={dash.page}
          pageCount={pages}
          label={T.list.pagination}
          onchange={(page) => dash.setPage(page)}
        />
      {/if}
    {/if}
  </section>
</main>

<Drawer
  bind:open={() => dash.selected !== null, (open) => !open && dash.close()}
  title={T.detail.title}
  closeLabel={T.actions.close}
>
  {#if dash.selected !== null}
    <FindingDetail finding={dash.selected} detail={dash.detail} failed={dash.detailFailed} />
  {/if}
</Drawer>

<Toaster position="bottom-right" />
<LiveAnnouncer />

<style>
  .brand {
    display: grid;
    line-height: 1.2;
  }
  .brand-name {
    font-family: var(--k-font-display);
    font-weight: var(--k-weight-display);
  }
  .brand-sub {
    font-size: var(--k-text-xs);
  }
  .page {
    display: grid;
    gap: var(--k-space-5);
    width: min(76rem, 100%);
    margin: 0 auto;
    padding: var(--k-space-5) var(--k-space-4) var(--k-space-8);
    outline: none;
  }
  .list {
    display: grid;
    gap: var(--k-space-4);
  }
  .list-head {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    justify-content: space-between;
    gap: var(--k-space-3) var(--k-space-5);
  }
  .list-head h2 {
    font-size: var(--k-text-lg);
    font-weight: var(--k-weight-heading);
  }
  .count {
    margin-inline-start: var(--k-space-2);
    font-size: var(--k-text-sm);
    font-weight: normal;
  }
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: var(--k-space-3) var(--k-space-5);
  }
  .skeleton {
    display: grid;
    gap: var(--k-space-2);
  }
  .empty-actions {
    display: grid;
    justify-items: center;
    gap: var(--k-space-3);
  }
  .hint {
    color: var(--k-fg-muted);
    font-size: var(--k-text-xs);
  }
  @media (max-width: 640px) {
    .brand-sub {
      display: none;
    }
  }
</style>
