import sys

if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required.")

from ruleproxy.server import main

main()
