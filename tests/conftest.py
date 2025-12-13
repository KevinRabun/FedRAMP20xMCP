"""
Pytest configuration and fixtures for FedRAMP 20x MCP tests.
"""

import pytest
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


@pytest.fixture
def data_loader():
    """Provide a DataLoader instance for tests."""
    return FedRAMPDataLoader()
