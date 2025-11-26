"""
Entry point for running the FedRAMP 20x MCP server as a module.

Usage:
    python -m fedramp_20x_mcp
    uv run fedramp-20x-mcp
"""

from .server import main

if __name__ == "__main__":
    main()
