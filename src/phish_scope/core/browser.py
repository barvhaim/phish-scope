"""
Browser Module

This module provides functions to interact with an MCP-based browser server.
"""

import logging
import base64
import json
from typing import Dict, Any, List, Optional
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

                content = ""
                if hasattr(result, "content") and isinstance(result.content, list):
                    # Combine all text components
                    content = "\n".join(
                        item.text if hasattr(item, "text") else str(item) for item in result.content
                    )
                else:
                    content = str(result)

                # Try to get title and final URL
                title = await _session_evaluate(session, "() => document.title")
                final_url = await _session_evaluate(session, "() => window.location.href")

                return {
                    "content": content,
                    "status": status,
                    "is_error": getattr(result, "isError", False),
                    "final_url": final_url or url,
                    "title": title or "Page Loaded",
                }
    except Exception as e:
        logger.error("Failed to load page via MCP: %s", e)
        return {"error": str(e), "status": "error"}


async def browser_evaluate(script: str) -> Any:
    """
    Executes JavaScript on the current page using the MCP browser server.
    """
    logger.info("Evaluating script via MCP")
    try:
        async with sse_client(MCP_SERVER_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                return await _session_evaluate(session, script)
    except Exception as e:
        logger.error("Failed to evaluate script via MCP: %s", e)
        raise


async def browser_get_content() -> str:
    """
    Gets the HTML content of the current page using the MCP browser server.
    """
    logger.info("Getting page content via MCP")
    try:
        return await browser_evaluate("() => document.documentElement.outerHTML")
    except Exception as e:
        logger.error("Failed to get content via MCP: %s", e)
        raise


async def browser_take_screenshot() -> bytes:
    """
    Takes a screenshot of the current page using the MCP browser server.
    """
    logger.info("Taking screenshot via MCP")
    try:
        async with sse_client(MCP_SERVER_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                result = await session.call_tool(
                    "browser_take_screenshot", arguments={"fullPage": True}
                )

                if hasattr(result, "isError") and result.isError:
                    raise RuntimeError(f"Screenshot failed: {result}")

                if hasattr(result, "content") and isinstance(result.content, list):
                    item = result.content[0]
                    if hasattr(item, "text"):
                        return base64.b64decode(item.text)
                    if hasattr(item, "data"):
                        return base64.b64decode(item.data)

                raise RuntimeError("Failed to extract screenshot data")
    except Exception as e:
        logger.error("Failed to take screenshot via MCP: %s", e)
        raise


async def browser_get_network_log() -> List[Dict[str, Any]]:
    """
    Gets the network log from the current page using the MCP browser server.
    """
    logger.info("Getting network log via MCP")
    try:
        # Note: This tool name depends on the specific MCP server implementation
        # Standard playwright-mcp-server might not have this, but let's try
        async with sse_client(MCP_SERVER_URL) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                # Some servers use browser_network_requests
                try:
                    result = await session.call_tool("browser_network_requests", {})
                    if hasattr(result, "isError") and result.isError:
                        return []

                    if hasattr(result, "content") and isinstance(result.content, list):
                        text = (
                            result.content[0].text if hasattr(result.content[0], "text") else "{}"
                        )
                        data = json.loads(text)
                        if isinstance(data, list):
                            return data
                        if isinstance(data, dict):
                            return data.get("requests", [])
                except:
                    logger.warning("browser_network_requests tool not available")
        return []
    except Exception as e:
        logger.error("Failed to get network log via MCP: %s", e)
        return []


async def _session_evaluate(session: ClientSession, script: str) -> Any:
    """Helper to evaluate script using an active session."""
    result = await session.call_tool("browser_evaluate", arguments={"script": script})

    if hasattr(result, "isError") and result.isError:
        return None

    if hasattr(result, "content") and isinstance(result.content, list):
        text = (
            result.content[0].text if hasattr(result.content[0], "text") else str(result.content[0])
        )
        try:
            return json.loads(text)
        except:
            return text
    return None
