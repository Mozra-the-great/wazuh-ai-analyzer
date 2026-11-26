<script lang="ts">
  import { Badge } from '@mozra-the-great/kern';
  import { SEVERITY_LABEL } from '../lib/strings.ts';
  import type { Severity } from '../lib/types.ts';

  interface Props {
    severity: Severity;
  }
  let { severity }: Props = $props();

  type Tone = 'neutral' | 'accent' | 'ok' | 'warn' | 'danger' | 'info';
  type Look = 'soft' | 'outline' | 'solid';
  // Five levels on six tones: the word is always shown, tone and fill only add to it.
  const STYLE: Record<Severity, { tone: Tone; look: Look }> = {
    critical: { tone: 'danger', look: 'solid' },
    high: { tone: 'danger', look: 'soft' },
    medium: { tone: 'warn', look: 'soft' },
    low: { tone: 'info', look: 'soft' },
    info: { tone: 'neutral', look: 'outline' },
  };
  const style = $derived(STYLE[severity]);
</script>

<Badge tone={style.tone} look={style.look}>{SEVERITY_LABEL[severity]}</Badge>
