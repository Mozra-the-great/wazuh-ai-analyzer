<script lang="ts">
  import { Tile, TileGrid } from '@mozra-the-great/kern';
  import { SEVERITY_LABEL, T } from '../lib/strings.ts';
  import { SEVERITIES, type Severity, type Stats } from '../lib/types.ts';

  interface Props {
    stats: Stats | null;
  }
  let { stats }: Props = $props();

  const nf = new Intl.NumberFormat('de-DE');
  const count = (level: Severity): string => (stats === null ? '–' : nf.format(stats.bySeverity[level]));
</script>

<TileGrid as="ul" min="9rem" class="sev-tiles" aria-label={T.tiles.label}>
  <Tile as="li">
    <div class="tile" data-level="all">
      <span class="num">{stats === null ? '–' : nf.format(stats.totalFindings)}</span>
      <span class="label">{T.tiles.all}</span>
    </div>
  </Tile>
  {#each SEVERITIES as level (level)}
    <Tile as="li">
      <div class="tile" data-level={level}>
        <span class="num">{count(level)}</span>
        <span class="label">{SEVERITY_LABEL[level]}</span>
      </div>
    </Tile>
  {/each}
</TileGrid>

<style>
  .tile {
    display: grid;
    gap: var(--k-space-1);
    padding: var(--k-space-1) 0;
  }
  .num {
    font-family: var(--k-font-display);
    font-size: var(--k-text-xl);
    font-weight: var(--k-weight-display);
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }
  .label {
    color: var(--k-fg-muted);
    font-size: var(--k-text-xs);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  /* Colour is an addition: every tile carries its word. */
  .tile[data-level='critical'] .num {
    color: var(--k-danger);
  }
  .tile[data-level='high'] .num {
    color: var(--k-warn);
  }
  .tile[data-level='low'] .num {
    color: var(--k-info);
  }
</style>
