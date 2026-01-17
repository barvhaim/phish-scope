"""
JavaScript Analyzer - Analyzes JavaScript for credential theft patterns.
"""

import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import Page

from phish_scope.core.analyzers import BaseAnalyzer


logger = logging.getLogger(__name__)


class JavaScriptAnalyzer(BaseAnalyzer):
    """
    Analyzes JavaScript code for phishing indicators:
    - Input/keydown event listeners on password fields
    - Credential serialization (JSON.stringify, FormData)
    - Fetch/XHR calls sending form data
    - Base64 encoding of credentials
    - Suspicious external script sources
    """

    # Suspicious patterns to detect
    SUSPICIOUS_PATTERNS = {
        "input_listener": r"addEventListener\s*\(\s*['\"]input['\"]",
        "keydown_listener": r"addEventListener\s*\(\s*['\"]keydown['\"]",
        "password_access": r"(type\s*===?\s*['\"]password['\"]|querySelector.*password)",
        "fetch_post": r"fetch\s*\([^)]*method\s*:\s*['\"]POST['\"]",
        "xhr_post": r"XMLHttpRequest.*\.send\s*\(",
        "json_stringify": r"JSON\.stringify",
        "formdata": r"new\s+FormData",
        "base64_encode": r"btoa\s*\(",
        "credential_keywords": r"(password|passwd|pwd|credential|login|username|email).*=",
        "data_exfil": r"(fetch|XMLHttpRequest|navigator\.sendBeacon).*\.(send|then)",
    }

    def __init__(self):
        super().__init__(name="javascript_analyzer")

    async def analyze(
        self,
        page: Optional["Page"] = None,
        browser_loader: Optional[Any] = None,
        network_log: Optional[List[Dict[str, Any]]] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Analyze JavaScript code for phishing patterns.

        Args:
            page: Playwright page object (for local mode)
            browser_loader: BrowserLoader instance (for MCP or abstracted access)
            network_log: Not used by this analyzer
            output_dir: Directory to save artifacts

        Returns:
            Dictionary containing JavaScript analysis findings
        """
        findings = {
            "inline_scripts_count": 0,
            "external_scripts_count": 0,
            "suspicious_patterns": [],
            "event_listeners": [],
            "external_sources": [],
            "evidence": [],
        }

        # Determine which evaluate function to use
        evaluate = self._get_evaluate_function(page, browser_loader)

        if not evaluate:
            logger.warning("No page context or browser_loader provided to JS analyzer")
            return findings

        try:
            # Extract all scripts
            scripts = await self._extract_scripts(evaluate)
            findings["inline_scripts_count"] = len(scripts["inline"])
            findings["external_scripts_count"] = len(scripts["external"])
            findings["external_sources"] = scripts["external"]

            # Analyze inline scripts
            all_js_code = "\n".join(scripts["inline"])

            # Detect suspicious patterns
            suspicious = self._detect_patterns(all_js_code)
            findings["suspicious_patterns"] = suspicious

            # Detect event listeners
            listeners = await self._detect_event_listeners(evaluate)
            findings["event_listeners"] = listeners

            # Save JavaScript artifacts
            if output_dir:
                artifacts_dir = output_dir / "artifacts"
                artifacts_dir.mkdir(exist_ok=True, parents=True)

                # Save inline scripts
                for idx, script in enumerate(scripts["inline"]):
                    if len(script) > 100:  # Only save substantial scripts
                        script_path = artifacts_dir / f"inline_script_{idx}.js"
                        with open(script_path, "w", encoding="utf-8") as f:
                            f.write(script)

                # Save suspicious snippets
                if suspicious:
                    snippets_path = artifacts_dir / "suspicious_js_snippets.txt"
                    with open(snippets_path, "w", encoding="utf-8") as f:
                        for pattern in suspicious:
                            f.write(f"\n{'='*60}\n")
                            f.write(f"Pattern: {pattern['pattern']}\n")
                            f.write(f"Matches: {pattern['count']}\n")
                            f.write(f"{'='*60}\n")
                            for match in pattern["matches"][:3]:  # First 3 matches
                                f.write(f"{match}\n\n")

            # Generate evidence
            findings["evidence"] = self._generate_evidence(findings)

            logger.info(
                f"JavaScript analysis complete: {len(suspicious)} suspicious patterns found"
            )

        except Exception as e:
            logger.error(f"JavaScript analysis failed: {str(e)}")
            findings["error"] = str(e)

        return findings

    def _get_evaluate_function(
        self, page: Optional["Page"], browser_loader: Optional[Any]
    ) -> Optional[Callable]:
        """Get the appropriate evaluate function based on available context."""
        if page is not None:
            return page.evaluate
        if browser_loader is not None and hasattr(browser_loader, "evaluate"):
            return browser_loader.evaluate
        return None

    async def _extract_scripts(self, evaluate: Callable) -> Dict[str, List[str]]:
        """Extract inline and external scripts."""
        scripts = await evaluate(
            """
            () => {
                const scriptTags = Array.from(document.querySelectorAll('script'));
                const inline = [];
                const external = [];

                scriptTags.forEach(script => {
                    if (script.src) {
                        external.push(script.src);
                    } else if (script.textContent) {
                        inline.push(script.textContent);
                    }
                });

                return { inline, external };
            }
        """
        )
        return scripts if scripts else {"inline": [], "external": []}

    def _detect_patterns(self, js_code: str) -> List[Dict[str, Any]]:
        """Detect suspicious JavaScript patterns."""
        suspicious = []

        for pattern_name, pattern_regex in self.SUSPICIOUS_PATTERNS.items():
            matches = re.finditer(pattern_regex, js_code, re.IGNORECASE)
            match_list = []

            for match in matches:
                # Get context around match (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(js_code), match.end() + 50)
                context = js_code[start:end].strip()
                match_list.append(context)

            if match_list:
                suspicious.append(
                    {
                        "pattern": pattern_name,
                        "count": len(match_list),
                        "matches": match_list,
                        "description": self._get_pattern_description(pattern_name),
                    }
                )

        return suspicious

    async def _detect_event_listeners(self, evaluate: Callable) -> List[Dict[str, Any]]:
        """Detect event listeners on input fields."""
        listeners = await evaluate(
            """
            () => {
                const inputs = Array.from(document.querySelectorAll('input'));
                const results = [];

                inputs.forEach((input, idx) => {
                    const events = [];

                    // Check for common event types
                    ['input', 'change', 'keydown', 'keyup', 'blur'].forEach(eventType => {
                        // This is a simplified check - real listeners are harder to detect
                        if (input['on' + eventType]) {
                            events.push(eventType);
                        }
                    });

                    if (events.length > 0) {
                        results.push({
                            index: idx,
                            type: input.type,
                            name: input.name || null,
                            id: input.id || null,
                            events: events
                        });
                    }
                });

                return results;
            }
        """
        )
        return listeners if listeners else []

    def _get_pattern_description(self, pattern_name: str) -> str:
        """Get human-readable description of pattern."""
        descriptions = {
            "input_listener": "Monitors user input in real-time",
            "keydown_listener": "Captures individual keystrokes",
            "password_access": "Accesses password field values",
            "fetch_post": "Sends POST request (potential data exfiltration)",
            "xhr_post": "Sends XHR POST request (potential data exfiltration)",
            "json_stringify": "Serializes data to JSON (common before exfiltration)",
            "formdata": "Creates FormData object (common for form submission)",
            "base64_encode": "Encodes data in Base64 (potential obfuscation)",
            "credential_keywords": "References credential-related variables",
            "data_exfil": "Sends data to external endpoint",
        }
        return descriptions.get(pattern_name, "Unknown pattern")

    def _generate_evidence(self, findings: Dict[str, Any]) -> List[str]:
        """Generate human-readable evidence from findings."""
        evidence = []

        if findings["inline_scripts_count"] > 0:
            evidence.append(f"Page contains {findings['inline_scripts_count']} inline script(s)")

        if findings["external_scripts_count"] > 0:
            evidence.append(f"Page loads {findings['external_scripts_count']} external script(s)")

            # Check for suspicious external sources
            trusted_domains = ["googleapis.com", "cloudflare.com", "jquery.com"]
            for src in findings["external_sources"]:
                if not any(domain in src for domain in trusted_domains):
                    evidence.append(f"External script from potentially suspicious source: {src}")

        for pattern in findings["suspicious_patterns"]:
            evidence.append(
                f"Detected {pattern['count']} instance(s) of '{pattern['pattern']}': "
                f"{pattern['description']}"
            )

        if findings["event_listeners"]:
            password_listeners = [
                listener
                for listener in findings["event_listeners"]
                if listener["type"] == "password"
            ]
            if password_listeners:
                evidence.append(
                    "Password field(s) have event listeners attached - "
                    "credentials may be captured before form submission"
                )

        return evidence
