#!/bin/bash
# Break-it scenarios (Day 3). Each deliberately weakens isolation so the canaries fire.
cd "$(dirname "$0")/.."
case "$1" in
  net)      # segmentation failure: put blue on red's network
    docker network connect canarychain_red_net "$(docker compose ps -q blue)"
    echo "blue is now on red_net. Test: docker compose exec blue python -c \"import socket;socket.create_connection(('red',9999),2)\""
    ;;
  net-undo) docker network disconnect canarychain_red_net "$(docker compose ps -q blue)" ;;
  leak)     # credential leak: arm stub LLM to echo red's token, then ask as blue
    TOK=$(docker compose exec -T red cat /data/.env | cut -d= -f2 | tr -d '\r\n')
    curl -s -XPOST localhost:8080/llm/demo/arm -d "{\"echo\":\"$TOK\"}"; echo
    # the chat request must really come FROM blue (gateway attributes by source IP)
    docker compose exec -T blue python -c "import urllib.request as u;r=u.Request('http://gateway:8080/llm/v1/chat',b'{}',{'Content-Type':'application/json'});print(u.urlopen(r,timeout=5).read().decode())"
    ;;
  *) echo "usage: $0 net|net-undo|leak" ;;
esac
