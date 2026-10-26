/** Fixed middle-ellipsis for Kong entity IDs shown as secondary text.
 * Full ID stays available via tooltip / copy; never use this as a name fallback. */
export function abbreviateId(id: string, head = 8, tail = 4): string {
  if (typeof id !== 'string' || id.length === 0) return id;
  const keep = head + tail + 1;
  if (id.length <= keep) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}
