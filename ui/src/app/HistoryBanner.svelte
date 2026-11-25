<script lang="ts">
  import { Alert, Progress } from '@mozra-the-great/kern';
  import { percent } from '../lib/format.ts';
  import { T } from '../lib/strings.ts';
  import type { HistoryProgress } from '../lib/types.ts';

  interface Props {
    history: HistoryProgress;
  }
  let { history }: Props = $props();

  // `files_total` is 0 until the first scan has counted the files.
  const total = $derived(Math.max(history.filesTotal, 1));
  const pct = $derived(percent(history.filesDone, total));
</script>

<Alert tone="info" title={T.history.title}>
  <div class="body wrap">
    <p>{T.history.body(history.filesDone, history.filesTotal, history.alertsScanned, history.batchesDone)}</p>
    <Progress label={T.history.progress} value={pct} showValue />
  </div>
</Alert>

<style>
  .body {
    display: grid;
    gap: var(--k-space-3);
  }
</style>
