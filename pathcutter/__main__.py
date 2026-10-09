"""Allow running as `python -m pathcutter`."""
import sys

from .cli import main

sys.exit(main())
