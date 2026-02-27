#!/bin/bash
set -e

sudo rm -rf /tmp/crates/*
./reset-database.sh
cargo run --release -- update-database
./build-docker.sh
