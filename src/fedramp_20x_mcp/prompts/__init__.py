"""
Prompt loader for FedRAMP 20x MCP Server.

This module provides functions to load prompt templates from external files.
"""
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Get the directory containing prompt files
PROMPTS_DIR = Path(__file__).parent


def load_prompt(prompt_name: str) -> str:
    """
    Load a prompt template from file.
    
    Args:
        prompt_name: Name of the prompt (without .txt extension)
        
    Returns:
        The prompt text content
        
    Raises:
        FileNotFoundError: If the prompt file doesn't exist
    """
    prompt_file = PROMPTS_DIR / f"{prompt_name}.txt"
    
    if not prompt_file.exists():
        logger.error(f"Prompt file not found: {prompt_file}")
        raise FileNotFoundError(f"Prompt template '{prompt_name}' not found")
    
    try:
        with open(prompt_file, 'r', encoding='utf-8') as f:
            content = f.read()
        logger.debug(f"Loaded prompt: {prompt_name} ({len(content)} chars)")
        return content
    except Exception as e:
        logger.error(f"Error loading prompt {prompt_name}: {e}")
        raise


def get_prompt(prompt_name: str, default: Optional[str] = None) -> str:
    """
    Get a prompt template, with optional fallback.
    
    Args:
        prompt_name: Name of the prompt (without .txt extension)
        default: Default text to return if prompt not found
        
    Returns:
        The prompt text content, or default if not found and default provided
    """
    try:
        return load_prompt(prompt_name)
    except FileNotFoundError:
        if default is not None:
            logger.warning(f"Prompt {prompt_name} not found, using default")
            return default
        raise
