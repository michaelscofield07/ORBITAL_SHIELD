import sys
from pathlib import Path

# Add project root to sys.path so 'simulator.xxx' imports resolve cleanly during pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
