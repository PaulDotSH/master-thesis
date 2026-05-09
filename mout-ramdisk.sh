sudo mkdir -p /tmp/crates

sudo mount -t tmpfs -o size=24G tmpfs /tmp/crates

df -h /tmp/crates