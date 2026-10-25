/** Sort one fresh collection with the original fingerprint/localeCompare
 * ordering. Keys live only in this call; rows and caller arrays stay intact. */
export function sortByFreshFingerprint<T>(rows: readonly T[], fingerprint: (row: T) => string): T[] {
  return rows.map(row => ({ row, key: fingerprint(row) }))
    .sort((left, right) => left.key.localeCompare(right.key))
    .map(entry => entry.row);
}
