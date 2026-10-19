#!/bin/bash
# Normal tenant activity for N seconds (default 120). Canaries must stay silent.
cd "$(dirname "$0")/.."
END=$((SECONDS + ${1:-120})); n=0
while [ $SECONDS -lt $END ]; do
  for t in red blue llm; do
    docker compose exec -T $t python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/work',timeout=3)" >/dev/null
  done
  docker compose exec -T red  python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/call/blue/health',timeout=3)" >/dev/null
  docker compose exec -T blue python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/call/llm/health',timeout=3)" >/dev/null
  n=$((n+5)); sleep 2
done
echo "normal traffic done: $n requests, expect 0 alerts"
