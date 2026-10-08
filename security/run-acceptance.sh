#!/usr/bin/env bash
# Phase 2 stages, shared by CI (.github/workflows/devsecops.yml) and local runs.
#   bash security/run-acceptance.sh                 all stages
#   bash security/run-acceptance.sh docker_scan     one stage (build, docker_scan, dast, acceptance_tests)
# Scans ONLY the Juice Shop container this script starts on 127.0.0.1:3000.
# Needs Docker (Linux containers) and curl. Windows: Git Bash with Docker Desktop running.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

OUT=security/out
IMAGE=${IMAGE:-juice-shop:acceptance}
NAME=juice-acceptance
# pinned tool images (update deliberately, not silently)
ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:2.17.0
TRIVY_IMAGE=aquasec/trivy:0.74.0
RUBY_IMAGE=ruby:3.2-bookworm

mkdir -p "$OUT" && chmod 777 "$OUT"

build() {
  echo "== build: target image from security/Dockerfile.acceptance"
  docker build -f security/Dockerfile.acceptance -t "$IMAGE" .
}

start_target() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -p 127.0.0.1:3000:3000 "$IMAGE" >/dev/null
  for _ in $(seq 1 150); do   # up to 5 min: first start is slow on a laptop
    curl -fs http://127.0.0.1:3000/ >/dev/null && return 0
    sleep 2
  done
  echo "target did not start"; docker logs "$NAME" | tail -30; return 1
}

stop_target() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }

docker_scan() {
  echo "== docker_scan: Trivy on the saved image (no Docker socket given to the scanner)"
  docker save "$IMAGE" -o "$OUT/image.tar"
  # default timeout (5 min) is too short for this image on a laptop
  docker run --rm -v "$PWD/$OUT:/out" "$TRIVY_IMAGE" image --input /out/image.tar --timeout 20m \
    --scanners vuln --severity HIGH,CRITICAL --format json --output /out/trivy.json
  docker run --rm -v "$PWD/$OUT:/out" "$TRIVY_IMAGE" image --input /out/image.tar --timeout 20m \
    --format cyclonedx --output /out/sbom-image.cdx.json
  rm -f "$OUT/image.tar"
}

dast() {
  # quick (default, every push/PR): traditional spider for 1 min.
  # full (ZAP_FULL=1: weekly, or on demand): also the Ajax spider, which drives a headless browser
  # through the Angular app, for 3 min. Same rules and same gate in both modes.
  local spider="-m 1"
  [ "${ZAP_FULL:-0}" = 1 ] && spider="-j -m 3"
  echo "== dast: OWASP ZAP baseline against the running build ($spider)"
  docker pull -q "$ZAP_IMAGE" >/dev/null &   # pull while the target starts
  start_target
  wait
  docker run --rm --network "container:$NAME" -v "$PWD/security:/zap/wrk:rw" "$ZAP_IMAGE" \
    zap-baseline.py -t http://127.0.0.1:3000 -c zap-rules.tsv \
    -J out/zap-report.json -r out/zap-report.html $spider -I || true
  stop_target
}

acceptance_tests() {
  echo "== acceptance_tests: Gauntlt (Lab 3) attacks against the running build"
  start_target
  docker run --rm --network "container:$NAME" -v "$PWD/security/gauntlt:/attacks:ro" "$RUBY_IMAGE" bash -c \
    'apt-get update -qq && apt-get install -y -qq nmap >/dev/null && gem install gauntlt --no-document >/dev/null && gauntlt /attacks/*.attack' \
    2>&1 | tee "$OUT/gauntlt.txt" || true
  stop_target
}

trap stop_target EXIT
stages=("$@")
[ ${#stages[@]} -eq 0 ] && stages=(build docker_scan dast acceptance_tests)
for s in "${stages[@]}"; do
  case "$s" in
    build|docker_scan|dast|acceptance_tests) "$s" ;;
    *) echo "unknown stage: $s"; exit 2 ;;
  esac
done
echo "== done: results in $OUT/"
ls -la "$OUT"
