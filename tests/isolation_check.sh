#!/bin/bash
# Proves isolation AND that tenants still work. Run after: docker compose up -d --build
cd "$(dirname "$0")/.."
pass=0; fail=0
chk() { # name want(0=should succeed,1=should fail) cmd...
  local name=$1 want=$2; shift 2
  "$@" >/dev/null 2>&1; local rc=$?
  if { [ "$want" = 0 ] && [ $rc = 0 ]; } || { [ "$want" = 1 ] && [ $rc != 0 ]; }; then
    echo "PASS  $name"; pass=$((pass+1))
  else echo "FAIL  $name"; fail=$((fail+1)); fi
}
py() { local svc=$1; shift; docker compose exec -T "$svc" python -c "$1"; }
get() { echo "import urllib.request as u;u.urlopen('$1',timeout=3)"; }

chk "red cannot reach blue directly"      1 py red  "$(get http://blue:8000/health)"
chk "blue cannot reach red directly"      1 py blue "$(get http://red:8000/health)"
chk "red cannot reach internet"           1 py red  "$(get http://1.1.1.1)"
chk "red can reach gateway"               0 py red  "$(get http://gateway:8080/red/health)"
chk "red->blue works THROUGH gateway"     0 py red  "$(get http://127.0.0.1:8000/call/blue/health)"
chk "tenant /work still functions"        0 py red  "$(get http://127.0.0.1:8000/work)"
chk "runs as non-root (uid 10001)"        0 py red  'import os,sys;sys.exit(0 if os.getuid()==10001 else 1)'
chk "root filesystem is read-only"        1 py red  'open("/evil","w")'
chk "/data is writable"                   0 py red  'open("/data/t","w")'
chk "decoy process rt_sync_red exists" 0 docker compose exec -T red sh -c 'grep -al 'rt_sync_[r]ed' /proc/[0-9]*/cmdline'
# attribution can't be spoofed: blue claims to be red, gateway must still log actor=blue
docker compose exec -T blue python -c "import urllib.request as u;u.urlopen(u.Request('http://gateway:8080/red/health',headers={'X-Tenant':'red'}),timeout=3)" >/dev/null 2>&1
chk "gateway attributes by IP, not header" 0 bash -c 'docker compose logs --tail 5 gateway | grep "\"actor\": \"blue\"" | grep -q spoof_claimed'
echo; echo "passed=$pass failed=$fail"; [ $fail = 0 ]
