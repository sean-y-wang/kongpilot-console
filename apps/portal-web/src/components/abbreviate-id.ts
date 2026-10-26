/** first8…last4 display form; the full id stays available via title / copy. */
export function abbreviateId(id: string | null | undefined): string {
  if (!id) return '—';
  return id.length > 14 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}
