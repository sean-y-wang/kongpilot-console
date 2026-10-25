const phases = new Set([
  'claimed', 'snapshot', 'snapshot-checked', 'step-check', 'step-ready',
  'native-complete', 'readback-complete', 'native-checked', 'metadata-prepare',
  'metadata-prepared', 'metadata-transaction', 'metadata-inspected',
  'metadata-authorized', 'metadata-applied', 'step-complete', 'failed',
]);
type Usage = Readonly<{ calls: number; pages: number; records: number; bytes: number }>;
type Sample = Readonly<Usage & { phase: string; step: number }>;

/** Bounded diagnostics, never execution authority. Only fixed phase names,
 * step ordinals and nonnegative counters can leave this collector. */
export class WorkflowExecutionObservation {
  private readonly samples: Sample[] = [];
  private omitted = 0;
  constructor(private readonly read: () => Usage) {}
  mark(phase: string, step = 0): void {
    try {
      if (!phases.has(phase) || !Number.isSafeInteger(step) || step < 0 || step > 10000) return;
      const value = this.read(), counters = ['calls', 'pages', 'records', 'bytes'] as const;
      if (counters.some(key => !Number.isSafeInteger(value?.[key]) || value[key] < 0)) return;
      const sample = Object.freeze({ phase, step, calls: value.calls, pages: value.pages, records: value.records, bytes: value.bytes });
      if (this.samples.length < 64) this.samples.push(sample);
      else { this.samples[63] = sample; this.omitted++; }
    } catch { /* Diagnostics cannot replace an original business outcome. */ }
  }
  snapshot(): Readonly<{ samples: readonly Sample[]; omitted: number }> {
    return Object.freeze({ samples: Object.freeze([...this.samples]), omitted: this.omitted });
  }
}
