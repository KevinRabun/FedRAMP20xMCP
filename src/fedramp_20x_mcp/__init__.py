"""
FedRAMP 20x MCP Server

An MCP (Model Context Protocol) server that provides access to FedRAMP 20x 
security requirements and controls with Azure-first guidance.
"""

__version__ = "0.11.0"
__author__ = "FedRAMP 20x MCP Server Contributors"
__license__ = "MIT"

from .server import main

__all__ = ["main"]
