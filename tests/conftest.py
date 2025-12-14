"""
Pytest configuration and fixtures for FedRAMP 20x MCP tests.
"""

import pytest
import asyncio
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


@pytest.fixture
def data_loader():
    """Provide a DataLoader instance for tests with data pre-loaded."""
    loader = FedRAMPDataLoader()
    # Load data synchronously for non-async tests
    asyncio.run(loader.load_data())
    return loader
