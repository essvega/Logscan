"""Entry point used by PyInstaller to build the standalone executables."""

import sys

from logscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
