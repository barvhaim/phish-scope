"""
Browser Module

This module provides functions to interact with an MCP-based browser server.
"""

import logging
from typing import Dict, Any
from mcp import ClientSession
from mcp.client.sse import sse_client

logger = logging.getLogger(__name__)

MCP_SERVER_URL = "http://localhost:8931/sse"


async def page_load(url: str) -> Dict[str, Any]:
    """
    Loads a page using the MCP browser server.

    Args:
        url: The URL to navigate to.

    Returns:
        A dictionary containing the result of the navigation.
    """
    logger.info("Connecting to MCP server at %s", MCP_SERVER_URL)

    try:
        async with sse_client(MCP_SERVER_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()

                logger.info("Calling browser_navigate for URL: %s", url)
                result = await session.call_tool("browser_navigate", arguments={"url": url})

                status = "success"
                if hasattr(result, "isError") and result.isError:
                    status = "error"

                return {
                    "content": result.content if hasattr(result, "content") else str(result),
                    "status": status,
                    "is_error": getattr(result, "isError", False),
                }
    except Exception as e:
        logger.error("Failed to load page via MCP: %s", e)
        return {"error": str(e), "status": "error"}
