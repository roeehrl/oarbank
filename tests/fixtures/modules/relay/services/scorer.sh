#!/bin/sh
# relay's scorer service (service protocol 1): a fixture, never started by the core tests.
case "$1" in
  fingerprint) echo '{"healthy": true, "pools": {"scorer": 2}, "reserved_mem_gb": 1.0}' ;;
  *) exit 0 ;;
esac
