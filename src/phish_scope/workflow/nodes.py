"""
Workflow Node Implementations

This module contains the node functions for the phishing analysis workflow.
"""

import logging
from langgraph.graph import END
from langgraph.types import Command

from phish_scope.workflow.state import WorkflowState


logger = logging.getLogger(__name__)


async def page_load_node(state: WorkflowState) -> Command:
    """
    Node that loads the target URL and captures initial page state.
    """

    url = state.get("url")
    logger.info("Loading page for URL: %s", url)

    return Command(
        goto=END,
        update={},
    )
