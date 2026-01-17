"""
ReportGenerator - Generates investigation-style reports.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Aggregates findings from all analyzers and generates:
    - Human-readable Markdown report
    - Machine-readable JSON report
    """

    async def generate_report(self, results: Dict[str, Any], output_dir: Path) -> Path:
        """
        Generate investigation report from analysis results.

        Args:
            results: Complete analysis results from all analyzers
            output_dir: Directory to save reports

        Returns:
            Path to the generated Markdown report
        """
        try:
            # Generate Markdown report
            markdown_path = output_dir / "report.md"
            markdown_content = self._generate_markdown(results)

            with open(markdown_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)

            # Generate JSON report
            json_path = output_dir / "report.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, default=str)

            logger.info(f"Reports generated: {markdown_path}")
            return markdown_path

        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            raise

    def _generate_markdown(self, results: Dict[str, Any]) -> str:
        """Generate Markdown investigation report."""

        url = results.get("url", "Unknown")
        timestamp = results.get("timestamp", datetime.utcnow().isoformat())
        findings = results.get("findings", {})
        page_load = results.get("page_load", {})

        # Build report
        lines = []
        lines.append("# PhishScope Investigation Report")
        lines.append("")
        lines.append(f"**Analysis Date:** {timestamp}")
        lines.append(f"**Target URL:** `{url}`")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        summary = self._generate_summary(findings)
        lines.append(summary)
        lines.append("")

        # AI Analysis Summary (if available)
        ai_analysis = findings.get("ai_analysis", {})
        if ai_analysis and ai_analysis.get("phishing_assessment"):
            assessment = ai_analysis["phishing_assessment"]
            lines.append("## AI Risk Assessment")
            lines.append("")
            lines.append(f"**Verdict:** {assessment.get('verdict', 'Unknown')}")
            lines.append(f"**Confidence:** {assessment.get('confidence', 'N/A')}%")
            lines.append("")
            if assessment.get("key_indicators"):
                lines.append("### Key Indicators:")
                for indicator in assessment["key_indicators"]:
                    lines.append(f"- {indicator}")
                lines.append("")
            if assessment.get("reasoning"):
                lines.append(f"**Reasoning:** {assessment['reasoning']}")
                lines.append("")

        # Page Load Information
        lines.append("## Page Load Information")
        lines.append("")
        if page_load.get("status") == "success":
            lines.append(f"- **Final URL:** `{page_load.get('final_url', 'N/A')}`")
            lines.append(f"- **Page Title:** {page_load.get('title', 'N/A')}")
            lines.append(f"- **HTTP Status:** {page_load.get('status_code', 'N/A')}")
            lines.append(f"- **Screenshot:** `{page_load.get('screenshot_path', 'N/A')}`")
        else:
            lines.append(f"**Page load failed:** {page_load.get('error', 'Unknown error')}")
        lines.append("")

        # DOM Analysis
        dom = findings.get("dom", {})
        if dom:
            lines.append("## DOM Analysis")
            lines.append("")
            lines.append(f"**Forms Detected:** {dom.get('forms_count', 0)}")
            lines.append("")

            if dom.get("evidence"):
                lines.append("### Key Findings:")
                for evidence in dom["evidence"]:
                    lines.append(f"- {evidence}")
                lines.append("")

            # Form details
            if dom.get("forms"):
                lines.append("### Form Details:")
                for idx, form in enumerate(dom["forms"], 1):
                    lines.append(f"\n**Form {idx}:**")
                    lines.append(f"- Action: `{form.get('action', 'none')}`")
                    lines.append(f"- Method: `{form.get('method', 'get')}`")
                    lines.append(
                        f"- Has Password Field: {'Yes' if form.get('has_password') else 'No'}"
                    )
                    lines.append(f"- Has Email Field: {'Yes' if form.get('has_email') else 'No'}")
                lines.append("")

        # JavaScript Analysis
        js = findings.get("javascript", {})
        if js:
            lines.append("## JavaScript Analysis")
            lines.append("")
            lines.append(f"**Inline Scripts:** {js.get('inline_scripts_count', 0)}")
            lines.append(f"**External Scripts:** {js.get('external_scripts_count', 0)}")
            lines.append("")

            if js.get("evidence"):
                lines.append("### Key Findings:")
                for evidence in js["evidence"]:
                    lines.append(f"- {evidence}")
                lines.append("")

            # Suspicious patterns
            if js.get("suspicious_patterns"):
                lines.append("### Suspicious JavaScript Patterns:")
                for pattern in js["suspicious_patterns"]:
                    lines.append(f"\n**{pattern['pattern']}** ({pattern['count']} occurrence(s))")
                    lines.append(f"- Description: {pattern['description']}")
                lines.append("")

        # Network Analysis
        network = findings.get("network", {})
        if network:
            lines.append("## Network Traffic Analysis")
            lines.append("")
            lines.append(f"**Total Requests:** {network.get('total_requests', 0)}")
            lines.append(f"**POST Requests:** {len(network.get('post_requests', []))}")
            lines.append("")

            if network.get("evidence"):
                lines.append("### Key Findings:")
                for evidence in network["evidence"]:
                    lines.append(f"- {evidence}")
                lines.append("")

            # Exfiltration candidates
            if network.get("exfiltration_candidates"):
                lines.append("### Potential Data Exfiltration Endpoints:")
                for candidate in network["exfiltration_candidates"][:5]:  # Top 5
                    lines.append(f"\n**{candidate['domain']}**")
                    lines.append(f"- URL: `{candidate['url']}`")
                    lines.append(f"- Suspicious Score: {candidate['suspicious_score']}")
                    lines.append(f"- Reasons: {', '.join(candidate['reasons'])}")
                lines.append("")

            # Third-party domains
            if network.get("third_party_domains"):
                lines.append("### Third-Party Domains:")
                for domain in network["third_party_domains"][:10]:  # Top 10
                    lines.append(f"- `{domain['domain']}` ({domain['request_count']} requests)")
                lines.append("")

        # Conclusion
        lines.append("## Conclusion")
        lines.append("")
        conclusion = self._generate_conclusion(findings)
        lines.append(conclusion)
        lines.append("")

        # Artifacts
        lines.append("## Artifacts")
        lines.append("")
        lines.append("The following artifacts were collected during analysis:")
        lines.append("- `screenshot.png` - Page screenshot")
        lines.append("- `artifacts/dom_snapshot.html` - Complete DOM snapshot")
        lines.append("- `artifacts/network_log.json` - Network traffic log")
        lines.append("- `artifacts/inline_script_*.js` - Extracted JavaScript code")
        lines.append("- `artifacts/suspicious_js_snippets.txt` - Suspicious code patterns")
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("*Generated by PhishScope - Evidence-Driven Phishing Analysis Agent*")

        return "\n".join(lines)

    def _generate_summary(self, findings: Dict[str, Any]) -> str:
        """Generate executive summary."""
        dom = findings.get("dom", {})
        js = findings.get("javascript", {})
        network = findings.get("network", {})

        summary_parts = []

        # Check for credential theft indicators
        has_forms = dom.get("forms_count", 0) > 0
        has_password = len(dom.get("password_fields", [])) > 0
        has_suspicious_js = len(js.get("suspicious_patterns", [])) > 0
        has_exfil = len(network.get("exfiltration_candidates", [])) > 0

        if has_forms and has_password:
            summary_parts.append("This page contains login forms with password fields.")

        if has_suspicious_js:
            summary_parts.append(
                f"JavaScript analysis detected {len(js.get('suspicious_patterns', []))} "
                "suspicious patterns commonly used in credential theft."
            )

        if has_exfil:
            summary_parts.append(
                f"Network analysis identified {len(network.get('exfiltration_candidates', []))} "
                "potential data exfiltration endpoints."
            )

        if not summary_parts:
            summary_parts.append("No significant phishing indicators were detected.")

        return " ".join(summary_parts)

    def _generate_conclusion(self, findings: Dict[str, Any]) -> str:
        """Generate conclusion."""
        dom = findings.get("dom", {})
        js = findings.get("javascript", {})
        network = findings.get("network", {})

        # Count indicators
        indicator_count = 0
        indicators = []

        if dom.get("forms_count", 0) > 0 and len(dom.get("password_fields", [])) > 0:
            indicator_count += 1
            indicators.append("credential collection forms")

        if len(js.get("suspicious_patterns", [])) >= 3:
            indicator_count += 1
            indicators.append("suspicious JavaScript behavior")

        if len(network.get("exfiltration_candidates", [])) > 0:
            indicator_count += 1
            indicators.append("data exfiltration endpoints")

        if indicator_count >= 2:
            conclusion = (
                f"**HIGH CONFIDENCE:** This page exhibits multiple phishing indicators "
                f"including {', '.join(indicators)}. The evidence suggests this is likely "
                "a phishing attack designed to steal user credentials."
            )
        elif indicator_count == 1:
            conclusion = (
                f"**MEDIUM CONFIDENCE:** This page shows some suspicious characteristics "
                f"({', '.join(indicators)}). Further investigation recommended."
            )
        else:
            conclusion = (
                "**LOW CONFIDENCE:** Limited phishing indicators detected. This may be a "
                "legitimate page or a sophisticated attack using advanced evasion techniques."
            )

        return conclusion
