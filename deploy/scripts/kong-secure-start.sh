#!/bin/sh
set -eu
umask 077

# Both addresses come from deployment configuration, never from an API request.
valid_ipv4() {
  printf '%s\n' "$1" | awk -F. 'NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i!~/^[0-9]+$/ || $i>255 || $i~/^0[0-9]/) exit 1}'
}
admin_address="${KONGOS_ADMIN_BIND_IP:?Set the fixed Kong management IPv4}"
bff_address="${KONGOS_BFF_ADMIN_IP:?Set the exact BFF management IPv4}"
for address in "$admin_address" "$bff_address"; do
  if ! valid_ipv4 "$address"; then
    echo 'Invalid fixed Admin management IPv4' >&2
    exit 1
  fi
  case "$address" in
    0.0.0.0|127.*|255.255.255.255)
      echo 'Admin management addresses must not be wildcard or loopback' >&2
      exit 1 ;;
  esac
done
if [ "$admin_address" = "$bff_address" ]; then
  echo 'Kong and BFF management addresses must differ' >&2
  exit 1
fi

prefix="${KONG_PREFIX:-/usr/local/kong}"
mkdir -p "$prefix"
# A single include preserves allow-before-deny order despite Lua pairs ordering.
printf 'allow %s;\ndeny all;\n' "$bff_address" > "$prefix/kongos-admin-access.conf"
cat > "$prefix/kongos-http.conf" <<'KONGOS_HTTP'
# Do not log request URI, query, headers or body: key-auth accepts query keys in1.5.
log_format kongos_safe '$time_iso8601 method=$request_method status=$status bytes=$body_bytes_sent request_time=$request_time upstream_time=$upstream_response_time';
KONGOS_HTTP
export KONG_NGINX_ADMIN_INCLUDE="$prefix/kongos-admin-access.conf"
export KONG_NGINX_HTTP_INCLUDE="$prefix/kongos-http.conf"
export KONG_ADMIN_LISTEN="$admin_address:8001,127.0.0.1:8001"
export KONG_ADMIN_ACCESS_LOG='/dev/stdout kongos_safe'
export KONG_PROXY_ACCESS_LOG='/dev/stdout kongos_safe'
# Native request-context errors include URI/query, even after access-log sanitizing.
# BFF redacted error codes/request IDs and safe status/timing logs remain available.
export KONG_ADMIN_ERROR_LOG='/dev/null'
export KONG_PROXY_ERROR_LOG='/dev/null'
# Kong 1.5 otherwise injects an additional external syslog error_log sink.
export KONG_ANONYMOUS_REPORTS='off'
exec /docker-entrypoint.sh kong docker-start
