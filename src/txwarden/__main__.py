"""``python -m txwarden`` is the same as the ``txwarden`` command."""
import sys

from .cli import main

sys.exit(main())
