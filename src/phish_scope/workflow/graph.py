"""
Workflow Graph Builder

This module constructs the LangGraph workflow for phishing analysis.
"""

from langgraph.graph import StateGraph
from phish_scope.workflow.nodes import (
    page_load_node,
    dom_analysis_node,
    js_analysis_node,
    network_analysis_node,
    ai_analysis_node,
    report_generation_node,
    cleanup_node,
)
from phish_scope.workflow.node_types import (
    PAGE_LOAD_NODE,
    DOM_ANALYSIS_NODE,
    JS_ANALYSIS_NODE,
    NETWORK_ANALYSIS_NODE,
    AI_ANALYSIS_NODE,
    REPORT_GENERATION_NODE,
    CLEANUP_NODE,
)
from phish_scope.workflow.state import WorkflowState


def build_graph():
    """
    Build and compile the phishing analysis workflow graph.

    The workflow follows this sequence:
    1. page_load_node - Load URL and capture page
    2. dom_analysis_node - Analyze DOM structure
    3. js_analysis_node - Analyze JavaScript code
    4. network_analysis_node - Analyze network traffic
    5. ai_analysis_node - AI-based assessment
    6. report_generation_node - Generate investigations reports
    7. cleanup_node - Final cleanup
    """
    flow = StateGraph(WorkflowState)

    # Add nodes
    flow.add_node(PAGE_LOAD_NODE, page_load_node)
    flow.add_node(DOM_ANALYSIS_NODE, dom_analysis_node)
    flow.add_node(JS_ANALYSIS_NODE, js_analysis_node)
    flow.add_node(NETWORK_ANALYSIS_NODE, network_analysis_node)
    flow.add_node(AI_ANALYSIS_NODE, ai_analysis_node)
    flow.add_node(REPORT_GENERATION_NODE, report_generation_node)
    flow.add_node(CLEANUP_NODE, cleanup_node)

    # Set entry point
    flow.set_entry_point(PAGE_LOAD_NODE)

    return flow.compile()
