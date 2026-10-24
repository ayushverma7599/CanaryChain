#!/bin/bash
# Break-it scenarios (Day 3). Each deliberately weakens isolation so the canaries fire.
cd "$(dirname "$0")/.."
case "$1" in
  net)      # segmentation failure: put blue on red's network
    docker network connect canarychain_red_net "$(docker compose ps -q blue)"
    echo "blue is now on red_net. Trip the network canary: docker compose exec blue python -c \"import socket;socket.create_connection(('canary-red',9999),2)\""
    ;;
  net-undo) docker network disconnect canarychain_red_net "$(docker compose ps -q blue)" ;;
  leak)     # credential leak: arm stub LLM to echo red's token, then ask as blue
    TOK=$(docker compose exec -T red cat /data/.env | cut -d= -f2 | tr -d '\r\n')
    curl -s -XPOST localhost:8080/llm/demo/arm -d "{\"echo\":\"$TOK\"}"; echo
    # the chat request must really come FROM blue (gateway attributes by source IP)
    docker compose exec -T blue python -c "import urllib.request as u;r=u.Request('http://gateway:8080/llm/v1/chat',b'{}',{'Content-Type':'application/json'});print(u.urlopen(r,timeout=5).read().decode())"
    ;;
  pid)      # PID-namespace leak: blue shares red's PID namespace, so it can see red's processes
    docker compose -f docker-compose.yml -f demo/pid-override.yml up -d blue
    echo "blue now shares red's PID namespace. The process canary probes every 30 s."
    ;;
  pid-undo) docker compose up -d blue ;;
  file)     # someone opens red's decoy file (inotify "opened" on the host sidecar)
    docker compose exec -T red cat /data/.rt_findings.json >/dev/null && echo "opened red's decoy file"
    ;;
  status)   # what the dashboard sees (through the frontend proxy on :8081)
    curl -s localhost:8081/api/verify; echo
    curl -s localhost:8081/api/canary; echo
    ;;
  tamper)   # edit one old audit row directly in SQLite, then /verify must fail
    docker compose exec -T core-api python -c "import sqlite3;c=sqlite3.connect('/data/security.sqlite3');c.execute(\"UPDATE audit_log SET event_type = event_type || '_edited' WHERE seq = (SELECT MIN(seq) FROM audit_log)\");c.commit();print('tampered with the oldest audit row')"
    echo "now run: $0 status   (the chain cannot be repaired; reset the demo with: docker compose down -v)"
    ;;
  *) echo "usage: $0 net|net-undo|pid|pid-undo|file|leak|status|tamper" ;;
esac
