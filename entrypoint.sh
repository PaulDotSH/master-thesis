#!/bin/sh
# cargo expects git folder
mkdir -p /usr/local/cargo/git

exec /app/crates_downloader "$@"
