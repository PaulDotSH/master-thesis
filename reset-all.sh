#!/bin/bash
set -e

sudo rm -rf /tmp/crates/*
redis-cli FLUSHALL
./reset-database.sh
cargo run --bin crates_downloader --release -- update-database
./build-docker.sh
cargo run --release --bin crates_downloader -- run-analysis


# compute-dependencies