#!/bin/sh
# Run from a reviewed local release/checkout, on the home computer itself.
set -eu
cd "$(dirname "$0")"
exec python3 ./install.py "${1:-install}"
