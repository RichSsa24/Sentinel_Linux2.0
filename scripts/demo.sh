#!/usr/bin/env bash
# Trigger an alert in Sentinel-Linux for demonstration purposes.

echo "Sentinel-Linux 2.0 - Synthetic Alert Trigger"
echo "This script simulates suspicious activity to trigger Sentinel detections."

# 1. Base64 execution (simulating a piped payload)
echo "[*] Triggering base64 execution detection..."
echo 'ls -la' | base64 | base64 -d | sh

# 2. Suspicious /tmp execution
echo "[*] Triggering suspicious /tmp execution..."
cp /bin/ls /tmp/totally_legit_binary
chmod +x /tmp/totally_legit_binary
/tmp/totally_legit_binary > /dev/null
rm /tmp/totally_legit_binary

# 3. Dummy cron persistence
echo "[*] Triggering cron persistence detection..."
echo "* * * * * root /bin/bash -c 'echo hello'" > /tmp/dummy_cron
# Normally we would move this to /etc/cron.d, but to be safe and avoid polluting the host,
# Sentinel FIM rule can be tested by touching the file if FIM is configured to watch /tmp.
touch /etc/cron.d/test_persistence 2>/dev/null || echo "  (Skipped cron drop due to permissions)"

echo "[+] Done. Check Sentinel logs, API, or Grafana dashboard for the emitted alerts."
