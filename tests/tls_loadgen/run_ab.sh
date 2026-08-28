#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <haproxy|rustN> <concurrency> [duration-seconds]" >&2
  echo "example: $0 rust4 64 30" >&2
  exit 2
}

[[ $# -ge 2 && $# -le 3 ]] || usage
case_name=$1
concurrency=$2
duration=${3:-30}
[[ "$case_name" == haproxy || "$case_name" =~ ^rust[1-9][0-9]*$ ]] || usage
[[ "$concurrency" =~ ^[1-9][0-9]*$ && "$concurrency" -le 4096 ]] || usage
[[ "$duration" =~ ^[1-9][0-9]*$ && "$duration" -le 3600 ]] || usage

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$script_dir/../.." && pwd)
loadgen="$script_dir/target/release/sni-tls-loadgen"
candidate="$repo/target/release/sni-fallback"
haproxy=${HAPROXY_BIN:-haproxy}
server_cpus=${SERVER_CPUS:-0-3}
load_cpus=${LOAD_CPUS:-4-10}
backend_cpus=${BACKEND_CPUS:-11}
haproxy_threads=${HAPROXY_THREADS:-4}
[[ "$haproxy_threads" =~ ^[1-9][0-9]*$ && "$haproxy_threads" -le 256 ]] || usage
tmpdir=$(mktemp -d /tmp/sni-fallback-ab.XXXXXX)
server_pid=
backend_pid=

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$backend_pid" ]]; then
    kill -TERM "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
  fi
  # The target is always the private directory returned by mktemp above.
  rm -r -- "$tmpdir"
}
trap cleanup EXIT

for command in cargo openssl taskset python3; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done
if [[ "$case_name" == haproxy ]]; then
  command -v "$haproxy" >/dev/null || { echo "HAProxy not found: $haproxy" >&2; exit 2; }
fi

cargo build --release --locked --manifest-path "$script_dir/Cargo.toml" >/dev/null
cargo build --release --locked --manifest-path "$repo/Cargo.toml" --bin sni-fallback >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=fallback-bench.invalid \
  -addext subjectAltName=DNS:fallback-bench.invalid \
  -addext basicConstraints=critical,CA:FALSE \
  -addext keyUsage=critical,digitalSignature,keyEncipherment \
  -addext extendedKeyUsage=serverAuth \
  -keyout "$tmpdir/key.pem" -out "$tmpdir/cert.pem" >/dev/null 2>&1
cp "$tmpdir/cert.pem" "$tmpdir/bundle.pem"
cat "$tmpdir/key.pem" >>"$tmpdir/bundle.pem"

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
backend_port=$(free_port)
listen_port=$(free_port)
metrics_port=$(free_port)

taskset -c "$backend_cpus" "$loadgen" backend \
  --listen "127.0.0.1:$backend_port" >"$tmpdir/backend.log" 2>&1 &
backend_pid=$!

cat >"$tmpdir/haproxy.cfg" <<EOF
global
  maxconn 100000
  nbthread $haproxy_threads
defaults
  mode http
  timeout connect 2s
  timeout client 10s
  timeout server 10s
frontend tls
  bind 127.0.0.1:$listen_port ssl crt $tmpdir/bundle.pem
  default_backend local
backend local
  server backend 127.0.0.1:$backend_port
EOF

wait_port() {
  local port=$1
  for _ in $(seq 1 100); do
    if timeout .1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
      return
    fi
    sleep .02
  done
  echo "listener did not start on port $port" >&2
  return 1
}
wait_port "$backend_port"

if [[ "$case_name" == rust* ]]; then
  runtime_workers=${case_name#rust}
  taskset -c "$server_cpus" "$candidate" \
    --listen "127.0.0.1:$listen_port" \
    --backend "127.0.0.1:$backend_port" \
    --metrics "127.0.0.1:$metrics_port" \
    --cert "$tmpdir/cert.pem" --key "$tmpdir/key.pem" \
    --allowed-sni fallback-bench.invalid \
    --runtime-workers "$runtime_workers" >"$tmpdir/server.log" 2>&1 &
else
  taskset -c "$server_cpus" "$haproxy" -db -f "$tmpdir/haproxy.cfg" \
    >"$tmpdir/server.log" 2>&1 &
fi
server_pid=$!
wait_port "$listen_port"

# Warm up code and certificate paths outside the measured interval.
taskset -c "$load_cpus" "$loadgen" load \
  --address "127.0.0.1:$listen_port" --cert "$tmpdir/cert.pem" \
  --concurrency 1 --duration 1 >/dev/null

start_ticks=$(awk '{print $14+$15}' "/proc/$server_pid/stat")
start_ns=$(date +%s%N)
load_result=$(taskset -c "$load_cpus" "$loadgen" load \
  --address "127.0.0.1:$listen_port" --cert "$tmpdir/cert.pem" \
  --concurrency "$concurrency" --duration "$duration")
end_ns=$(date +%s%N)
end_ticks=$(awk '{print $14+$15}' "/proc/$server_pid/stat")
rss_kib=$(awk '/^VmRSS:/ {print $2}' "/proc/$server_pid/status")
clock_ticks=$(getconf CLK_TCK)
elapsed=$(awk -v start="$start_ns" -v end="$end_ns" \
  'BEGIN { printf "%.6f", (end-start)/1000000000 }')
cpu=$(awk -v start="$start_ticks" -v end="$end_ticks" \
  -v hz="$clock_ticks" -v elapsed="$elapsed" \
  'BEGIN { printf "%.3f", 100*(end-start)/hz/elapsed }')

echo "server=$case_name concurrency=$concurrency server_cpu_percent=$cpu rss_kib=$rss_kib $load_result"
