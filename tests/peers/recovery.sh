#!/usr/bin/env bash
# Restart an encrypted peer on the same endpoint, with a decoy at the old namespace index.
set -euo pipefail
exec bash "$(dirname "$0")/protocol.sh" recovery
