sudo mkdir -p /tmp/crates

sudo mount -t tmpfs -o size=4G tmpfs /tmp/crates

df -h /tmp/crates