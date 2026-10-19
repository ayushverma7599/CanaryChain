#!/bin/bash
set -e
# Process-canary decoy (Harshit's probe looks for this name in other tenants)
(exec -a rt_sync_daemon sleep infinity) &
exec python /app/tenant.py
