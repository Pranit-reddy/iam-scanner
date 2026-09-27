"""Entry point for `python -m iam_scanner` and the `iam-scanner` script."""

import sys

from iam_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
