"""
Workflow Node Implementations

This module contains the node functions for the phishing analysis workflow.
"""

import logging
from langgraph.graph import END
from langgraph.types import Command

from phish_scope.core.browser import page_load
from phish_scope.workflow.state import WorkflowState


logger = logging.getLogger(__name__)


async def page_load_node(state: WorkflowState) -> Command:
    """
    Node that loads the target URL and captures initial page state using MCP.
    """

    url = state.get("url")
    logger.info("Loading page for URL: %s", url)

    if not url:
        return Command(
            goto=END,
            update={"error": "No URL provided in state"},
        )

    result = await page_load(url)

    if result.get("status") == "error":
        return Command(
            goto=END,
            update={"error": result.get("error"), "page_load_result": result},
        )

    return Command(
        goto=END,
        update={"page_load_result": result},
    )
