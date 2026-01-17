"""
Workflow State Management

This module defines the state structure and status enum for the phishing analysis workflow.
"""

from enum import Enum
from typing import Optional, Dict, List, Any
from typing_extensions import TypedDict


class WorkflowStatus(str, Enum):
    """Enum representing possible workflow statuses."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkflowState(TypedDict):
    """
    Represents the state of a phishing analysis workflow.

    Attributes:
        workflow_id (str): Unique identifier for the workflow.
        url (str): Target URL being analyzed.
        output_dir (str): Directory for saving artifacts and reports.
        page_load_result (Optional[Dict]): Results from page loading.
        network_log (Optional[List]): Network traffic log captured during page load.
        dom_findings (Optional[Dict]): DOM analysis results.
        js_findings (Optional[Dict]): JavaScript analysis results.
        network_findings (Optional[Dict]): Network traffic analysis results.
        ai_findings (Optional[Dict]): LLM-based analysis results.
        report_path (Optional[str]): Path to generated report.
        status (WorkflowStatus): Current status of the workflow.
        start_time (Optional[str]): ISO 8601 formatted start time.
        end_time (Optional[str]): ISO 8601 formatted end time.
        error (Optional[str]): Error message if workflow failed.
    """

    workflow_id: str
    url: str
    output_dir: str
    page_load_result: Optional[Dict]
    network_log: Optional[List[Dict[str, Any]]]
    dom_findings: Optional[Dict]
    js_findings: Optional[Dict]
    network_findings: Optional[Dict]
    ai_findings: Optional[Dict]
    report_path: Optional[str]
    status: WorkflowStatus
    start_time: Optional[str]
    end_time: Optional[str]
    error: Optional[str]
