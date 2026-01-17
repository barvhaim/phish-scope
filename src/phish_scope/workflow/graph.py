"""
Workflow Graph Builder

This module constructs the LangGraph workflow for phishing analysis.
"""

from langgraph.graph import StateGraph
from phish_scope.workflow.nodes import (
    page_load_node,
)
from phish_scope.workflow.node_types import (
    PAGE_LOAD_NODE,
)
from phish_scope.workflow.state import WorkflowState


def build_graph():
    """
    Build and compile the phishing analysis workflow graph.

    The workflow follows this sequence:
    1. page_load_node - Load URL and capture page

    Returns:
        Compiled LangGraph workflow
    """
    flow = StateGraph(WorkflowState)

    # Add nodes
    flow.add_node(PAGE_LOAD_NODE, page_load_node)

    # Set entry point
    flow.set_entry_point(PAGE_LOAD_NODE)

    return flow.compile()
