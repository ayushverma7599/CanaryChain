#!/bin/bash
# Paced demo: pauses after each step so you can refresh the dashboard and take a screenshot.
cd "$(dirname "$0")/.."
pause() { echo; read -r -p ">>> $1  [press Enter to continue] " _; }

echo "Open http://127.0.0.1:8081 and hard-refresh with Ctrl+Shift+R."
pause "SCREENSHOT 1: clean state (0 events, chain Verified, 0 entries checked)."

./demo/breakit.sh leak
pause "Click 'Refresh all'. SCREENSHOT 2: credential trip, severity 0.72."

./demo/breakit.sh file
pause "Click 'Refresh all'. SCREENSHOT 3: file trip, severity 0.384."

./demo/breakit.sh net
docker compose exec -T blue python -c "import socket;socket.create_connection(('canary-red',9999),2).close()"
./demo/breakit.sh net-undo
pause "Click 'Refresh all'. SCREENSHOT 4: network trip, severity 0.504."

echo "head_hash saved OUTSIDE the system (also written to /tmp/head_hash.txt):"
curl -s localhost:8081/api/verify | python3 -c "import sys,json;print(json.load(sys.stdin)['head_hash'])" | tee /tmp/head_hash.txt
pause "Click 'Verify chain'. SCREENSHOT 5: Verified, entries checked, head hash (must match the line above)."

./demo/breakit.sh truncate
pause "Click 'Verify chain'. SCREENSHOT 5b: still Verified, but fewer entries and a DIFFERENT head hash than the one saved above (the external anchor catches deletions)."

./demo/breakit.sh tamper
pause "Click 'Verify chain'. SCREENSHOT 6: Verification failed + first failing entry."

echo "Done. Reset when you have the screenshots:  docker compose down -v && docker compose up -d"
