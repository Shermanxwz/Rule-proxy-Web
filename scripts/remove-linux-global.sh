#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(id -u)" -ne 0 ]; then
    exec sudo /usr/bin/python3 -I "$root/scripts/install-linux-global.py" --remove
fi
exec /usr/bin/python3 -I "$root/scripts/install-linux-global.py" --remove
