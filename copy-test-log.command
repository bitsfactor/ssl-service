#!/usr/bin/env bash
# Copy the live test log to the workspace folder so the agent can read it.
cp /tmp/ssl-service-static-ips-test.log "$(dirname "${BASH_SOURCE[0]}")/test-static-ips.log"
echo "copied to test-static-ips.log"
