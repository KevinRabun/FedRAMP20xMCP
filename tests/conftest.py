"""
Pytest configuration and fixtures for FedRAMP 20x MCP tests.

Includes markers for:
- critical: Tests that MUST pass for build to succeed
- security: Security-related tests  
- adversarial: Adversarial testing (hallucination, misinformation, etc.)
- hallucination: Tests for fabricated information
- misinformation: Tests for confused definitions
- edge_case: Edge case handling tests
- injection: Injection vulnerability tests
- robustness: Robustness and stability tests
"""

import pytest
import asyncio
from typing import Generator
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "critical: marks tests as critical for build pass/fail")
    config.addinivalue_line("markers", "security: marks security-related tests")
    config.addinivalue_line("markers", "adversarial: marks adversarial tests")
    config.addinivalue_line("markers", "hallucination: marks hallucination detection tests")
    config.addinivalue_line("markers", "misinformation: marks misinformation detection tests")
    config.addinivalue_line("markers", "edge_case: marks edge case tests")
    config.addinivalue_line("markers", "injection: marks injection resistance tests")
    config.addinivalue_line("markers", "robustness: marks robustness tests")


@pytest.fixture
def data_loader():
    """Provide a DataLoader instance for tests with data pre-loaded."""
    loader = FedRAMPDataLoader()
    # Load data synchronously for non-async tests
    asyncio.run(loader.load_data())
    return loader


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
