"""
Workflow Node Implementations

This module contains the node functions for the phishing analysis workflow.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from langgraph.graph import END
from langgraph.types import Command

from phish_scope.workflow.state import WorkflowState, WorkflowStatus
from phish_scope.workflow.node_types import (
    DOM_ANALYSIS_NODE,
    JS_ANALYSIS_NODE,
    NETWORK_ANALYSIS_NODE,
    AI_ANALYSIS_NODE,
    REPORT_GENERATION_NODE,
    CLEANUP_NODE,
)
from phish_scope.core.browser import (
    page_load,
    browser_evaluate,
    browser_get_content,
    browser_take_screenshot,
    browser_get_network_log,
)
import json
from phish_scope.llm.clients import get_chat_llm_client
from phish_scope.llm.prompts import get_prompts


logger = logging.getLogger(__name__)


async def page_load_node(state: WorkflowState) -> Command:
    """
    Node that loads the target URL and captures initial page state using MCP.
    """
    url = state.get("url")
    output_dir = Path(state.get("output_dir", "./reports"))
    workflow_id = state.get("workflow_id")

    if not url:
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED,
                "error": "No URL provided",
            },
        )

    try:
        logger.info(f"Loading page: {url}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Load page
        result = await page_load(url)

        if result.get("status") == "error":
            return Command(
                goto=CLEANUP_NODE,
                update={
                    "page_load_result": result,
                    "status": WorkflowStatus.FAILED,
                    "error": result.get("error", "Page load failed"),
                },
            )

        # Capture screenshot
        try:
            screenshot_bytes = await browser_take_screenshot()
            screenshot_path = output_dir / "screenshot.png"
            screenshot_path.write_bytes(screenshot_bytes)
            result["screenshot_path"] = str(screenshot_path)
            logger.info(f"Screenshot saved to {screenshot_path}")
        except Exception as e:
            logger.warning(f"Failed to capture screenshot: {e}")

        # Capture network log
        network_log = await browser_get_network_log()
        result["network_log"] = network_log

        return Command(
            goto=DOM_ANALYSIS_NODE,
            update={
                "page_load_result": result,
                "network_log": network_log,
                "start_time": datetime.now().isoformat(),
            },
        )

    except Exception as exc:
        logger.exception("Page load failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED,
                "error": str(exc),
            },
        )


async def dom_analysis_node(state: WorkflowState) -> Command:
    """Node that performs DOM analysis."""
    from phish_scope.core.analyzers.dom import DOMAnalyzer

    output_dir = Path(state.get("output_dir", "./reports"))

    try:
        logger.info("Analyzing DOM...")

        # Create a proxy for the browser that uses MCP tools
        class MCPBrowserProxy:
            async def evaluate(self, script: str) -> Any:
                return await browser_evaluate(script)

            async def get_content(self) -> str:
                return await browser_get_content()

        analyzer = DOMAnalyzer()
        findings = await analyzer.analyze(browser_loader=MCPBrowserProxy(), output_dir=output_dir)

        return Command(
            goto=JS_ANALYSIS_NODE,
            update={"dom_findings": findings},
        )

    except Exception as exc:
        logger.exception("DOM analysis failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED,
                "error": str(exc),
            },
        )


async def js_analysis_node(state: WorkflowState) -> Command:
    """Node that performs JavaScript analysis."""
    from phish_scope.core.analyzers.javascript import JavaScriptAnalyzer

    output_dir = Path(state.get("output_dir", "./reports"))

    try:
        logger.info("Analyzing JavaScript...")

        class MCPBrowserProxy:
            async def evaluate(self, script: str) -> Any:
                return await browser_evaluate(script)

            async def get_content(self) -> str:
                return await browser_get_content()

        analyzer = JavaScriptAnalyzer()
        findings = await analyzer.analyze(browser_loader=MCPBrowserProxy(), output_dir=output_dir)

        return Command(
            goto=NETWORK_ANALYSIS_NODE,
            update={"js_findings": findings},
        )

    except Exception as exc:
        logger.exception("JavaScript analysis failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED,
                "error": str(exc),
            },
        )


async def network_analysis_node(state: WorkflowState) -> Command:
    """Node that performs network traffic analysis."""
    from phish_scope.core.analyzers.network import NetworkAnalyzer

    output_dir = Path(state.get("output_dir", "./reports"))
    network_log = state.get("network_log", [])

    try:
        logger.info("Analyzing network traffic...")

        analyzer = NetworkAnalyzer()
        findings = await analyzer.analyze(network_log=network_log, output_dir=output_dir)

        return Command(
            goto=AI_ANALYSIS_NODE,
            update={"network_findings": findings},
        )

    except Exception as exc:
        logger.exception("Network analysis failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED,
                "error": str(exc),
            },
        )


async def ai_analysis_node(state: WorkflowState) -> Command:
    """Node that performs LLM-based analysis."""
    url = state.get("url")
    dom_findings = state.get("dom_findings", {})
    js_findings = state.get("js_findings", {})
    network_findings = state.get("network_findings", {})

    try:
        logger.info("Running AI analysis...")

        # 1. Initialize LLM client
        import os

        model_name = os.getenv("LLM_MODEL", "meta-llama/llama-3-3-70b-instruct")
        llm = get_chat_llm_client(model_name=model_name)

        # 2. Get prompt templates
        prompts = get_prompts("phishing_analysis")
        if not prompts or "phishing_analysis" not in prompts:
            raise ValueError("Phishing analysis prompt template not found")

        prompt_config = prompts["phishing_analysis"]
        system_prompt = prompt_config.get("system_prompt", "")
        user_prompt_template = prompt_config.get("user_prompt", "")

        # 3. Format user prompt
        user_prompt = user_prompt_template.replace("{{url}}", str(url))
        user_prompt = user_prompt.replace("{{dom_findings}}", json.dumps(dom_findings, indent=2))
        user_prompt = user_prompt.replace("{{js_findings}}", json.dumps(js_findings, indent=2))
        user_prompt = user_prompt.replace(
            "{{network_findings}}", json.dumps(network_findings, indent=2)
        )

        # 4. Call LLM
        messages = [("system", system_prompt), ("user", user_prompt)]

        response = await llm.ainvoke(messages)

        # 5. Parse response content
        # LangChain response content can be string or list of dicts/strings
        content = response.content
        logger.info(f"LLM Response received. Content length: {len(content) if content else 0}")
        logger.debug(f"LLM Response content: {content}")

        if not isinstance(content, str):
            content = str(content)

        if not content.strip():
            raise ValueError("LLM returned an empty response")
        # Extract JSON from potential triple backticks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        findings = json.loads(content)

        # Ensure ai_enabled is True when coming from LLM
        findings["ai_enabled"] = True

        return Command(
            goto=REPORT_GENERATION_NODE,
            update={"ai_findings": findings},
        )

    except Exception as exc:
        logger.warning(f"AI analysis failed, using fallback: {exc}")
        findings = _fallback_assessment(dom_findings, js_findings, network_findings)
        return Command(
            goto=REPORT_GENERATION_NODE,
            update={"ai_findings": findings},
        )


async def report_generation_node(state: WorkflowState) -> Command:
    """Node that generates the analysis report."""
    from phish_scope.core.report_generator import ReportGenerator

    output_dir = Path(state.get("output_dir", "./reports"))

    try:
        logger.info("Generating report...")

        # Build results structure
        results = {
            "url": state.get("url"),
            "timestamp": state.get("start_time"),
            "page_load": state.get("page_load_result", {}),
            "findings": {
                "dom": state.get("dom_findings", {}),
                "javascript": state.get("js_findings", {}),
                "network": state.get("network_findings", {}),
                "ai_analysis": state.get("ai_findings", {}),
            },
        }

        generator = ReportGenerator()
        report_path = await generator.generate_report(results, output_dir)

        return Command(
            goto=CLEANUP_NODE,
            update={
                "report_path": str(report_path),
                "status": WorkflowStatus.COMPLETED,
            },
        )

    except Exception as exc:
        logger.exception("Report generation failed")
        return Command(
            goto=CLEANUP_NODE,
            update={
                "status": WorkflowStatus.FAILED,
                "error": str(exc),
            },
        )


async def cleanup_node(state: WorkflowState) -> Command:
    """
    Node that performs cleanup operations.
    """
    # In MCP mode, we might want to close the browser session if we implemented a session manager
    logger.info("Cleaning up workflow...")

    # Preserve FAILED status if already set, otherwise mark as COMPLETED
    current_status = state.get("status")
    final_status = (
        current_status if current_status == WorkflowStatus.FAILED else WorkflowStatus.COMPLETED
    )

    return Command(
        goto=END,
        update={
            "status": final_status,
            "end_time": datetime.now().isoformat(),
        },
    )


def _fallback_assessment(dom_findings: dict, js_findings: dict, network_findings: dict) -> dict:
    """Fallback rule-based assessment when LLM is unavailable."""
    risk_score = 0
    indicators = []

    # DOM-based scoring
    if dom_findings.get("forms_count", 0) > 0:
        risk_score += 30
        indicators.append("Login form detected")

    if dom_findings.get("password_fields"):
        risk_score += 25
        indicators.append("Password fields present")

    # JavaScript-based scoring
    if js_findings.get("suspicious_patterns"):
        pattern_count = len(js_findings["suspicious_patterns"])
        risk_score += min(pattern_count * 10, 30)
        indicators.append(f"{pattern_count} suspicious JS patterns")

    # Network-based scoring
    if network_findings.get("exfiltration_candidates"):
        risk_score += 25
        indicators.append("Potential data exfiltration endpoints")

    # Determine verdict
    if risk_score >= 60:
        verdict = "High Risk"
    elif risk_score >= 30:
        verdict = "Medium Risk"
    else:
        verdict = "Low Risk"

    return {
        "ai_enabled": False,
        "phishing_assessment": {
            "verdict": verdict,
            "confidence": min(risk_score, 95),
            "key_indicators": indicators if indicators else ["No significant indicators"],
            "reasoning": f"Rule-based assessment (AI unavailable). Risk score: {risk_score}/100",
            "attack_type": "Credential phishing" if risk_score >= 50 else "Unknown",
        },
    }
