#!/usr/bin/env bash
set -euo pipefail

service=sni-fallback-canary.service
host=paruscamp.com
metrics=http://127.0.0.1:19091/

systemctl is-active --quiet "$service"
curl --fail --insecure --silent --show-error --max-time 5 \
  --resolve "$host:14443:127.0.0.1" "https://$host:14443/" >/dev/null
curl --fail --silent --show-error --max-time 3 "$metrics" \
  | grep --quiet '^sni_fallback_connections_active '
