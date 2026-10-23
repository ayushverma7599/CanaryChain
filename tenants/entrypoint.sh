#!/bin/bash
set -e
# Process-canary decoy: one name per tenant (rt_sync_red, ...) so the probe can tell tenants apart
(exec -a rt_sync_${TENANT_NAME} sleep infinity) &
exec python /app/tenant.py
