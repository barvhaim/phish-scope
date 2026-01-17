"""
Workflow State Management

This module defines the state structure and status enum for the phishing analysis workflow.
"""

from typing import Optional, Dict
from typing_extensions import TypedDict


class WorkflowState(TypedDict):
    """
    Represents the state of a phishing analysis workflow.

    Attributes:
        url (str): The URL being analyzed.
        page_load_result (Optional[Dict]): The result of the page load operation.
        error (Optional[str]): Any error encountered during the workflow.
    """

    url: str
    page_load_result: Optional[Dict]
    error: Optional[str]
