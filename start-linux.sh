#!/usr/bin/env sh
set -eu
cd -- "$(dirname -- "$0")"
# The first run, or the first run after an update that needs new components, sets things up.
if ! sh ./setup-linux.sh --check; then
    sh ./setup-linux.sh --for-start
fi
exec python3 Run-RuleProxy.py "$@"
