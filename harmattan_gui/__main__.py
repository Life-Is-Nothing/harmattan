#!/usr/bin/env python3
"""Entry point: python -m harmattan_gui"""

import sys
import os

# Add parent directory to path so we can import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harmattan_gui.app import main

if __name__ == "__main__":
    sys.exit(main())
