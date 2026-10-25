#!/bin/sh
set -eu
# Kong's migration list exits 3 when a fresh database needs bootstrap.
# Every other failure stops startup; connection failures are not mistaken for fresh DB.
if kong migrations list; then
  exit 0
else
  migration_status=$?
fi
if [ "$migration_status" -eq 3 ]; then
  exec kong migrations bootstrap
fi
if [ "$migration_status" -eq 4 ] || [ "$migration_status" -eq 5 ]; then
  kong migrations up
  exec kong migrations finish
fi
echo "Kong migrations list failed (status $migration_status); refusing to guess database state." >&2
exit "$migration_status"
