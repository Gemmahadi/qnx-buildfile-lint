#!/bin/sh
# Run the full test suite (stdlib unittest, no dependencies).
set -e
cd "$(dirname "$0")"
python3 -m unittest discover -s tests -v "$@"
