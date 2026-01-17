"""
DOM Analyzer - Analyzes DOM structure for phishing indicators.
"""

import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from playwright.async_api import Page

from phish_scope.core.analyzers import BaseAnalyzer


logger = logging.getLogger(__name__)


class DOMAnalyzer(BaseAnalyzer):
    """
    Inspects DOM for phishing indicators:
    - Login forms and password fields
    - Hidden inputs and overlays
    - Suspicious iframes
    - DOM mutations after page load
    """

    def __init__(self):
        super().__init__(name="dom_analyzer")

    async def analyze(
        self,
        page: Optional["Page"] = None,
        browser_loader: Optional[Any] = None,
        network_log: Optional[List[Dict[str, Any]]] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Analyze DOM structure for phishing indicators.

        Args:
            page: Playwright page object (for local mode)
            browser_loader: BrowserLoader instance (for MCP or abstracted access)
            network_log: Not used by this analyzer
            output_dir: Directory to save artifacts

        Returns:
            Dictionary containing DOM analysis findings
        """
        findings = {
            "forms_count": 0,
            "password_fields": [],
            "hidden_inputs": [],
            "suspicious_iframes": [],
            "overlays": [],
            "dom_mutations": [],
            "evidence": [],
        }

        # Determine which evaluate function to use
        evaluate = self._get_evaluate_function(page, browser_loader)
        get_content = self._get_content_function(page, browser_loader)

        if not evaluate:
            logger.warning("No page context or browser_loader provided to DOM analyzer")
            return findings

        try:
            # Detect forms
            forms = await self._detect_forms(evaluate)
            findings["forms_count"] = len(forms)
            findings["forms"] = forms

            # Detect password fields
            password_fields = await self._detect_password_fields(evaluate)
            findings["password_fields"] = password_fields

            # Detect hidden inputs
            hidden_inputs = await self._detect_hidden_inputs(evaluate)
            findings["hidden_inputs"] = hidden_inputs

            # Detect suspicious iframes
            iframes = await self._detect_iframes(evaluate)
            findings["suspicious_iframes"] = iframes

            # Detect overlays
            overlays = await self._detect_overlays(evaluate)
            findings["overlays"] = overlays

            # Save DOM snapshot
            if output_dir and get_content:
                dom_html = await get_content()
                artifacts_dir = output_dir / "artifacts"
                artifacts_dir.mkdir(exist_ok=True, parents=True)
                with open(artifacts_dir / "dom_snapshot.html", "w", encoding="utf-8") as f:
                    f.write(dom_html)

            # Generate evidence
            findings["evidence"] = self._generate_evidence(findings)

            logger.info(f"DOM analysis complete: {len(findings['evidence'])} findings")

        except Exception as e:
            logger.error(f"DOM analysis failed: {str(e)}")
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

    def _get_content_function(
        self, page: Optional["Page"], browser_loader: Optional[Any]
    ) -> Optional[Callable]:
        """Get the appropriate content retrieval function."""
        if page is not None:
            return page.content
        if browser_loader is not None and hasattr(browser_loader, "get_content"):
            return browser_loader.get_content
        return None

    async def _detect_forms(self, evaluate: Callable) -> List[Dict[str, Any]]:
        """Detect all forms on the page."""
        forms = await evaluate(
            """
            () => {
                const forms = Array.from(document.querySelectorAll('form'));
                return forms.map((form, idx) => ({
                    index: idx,
                    action: form.action || 'none',
                    method: form.method || 'get',
                    id: form.id || null,
                    class: form.className || null,
                    input_count: form.querySelectorAll('input').length,
                    has_password: form.querySelector('input[type="password"]') !== null,
                    has_email: form.querySelector('input[type="email"]') !== null,
                    has_submit: form.querySelector('input[type="submit"], button[type="submit"]') !== null
                }));
            }
        """
        )
        return forms if forms else []

    async def _detect_password_fields(self, evaluate: Callable) -> List[Dict[str, Any]]:
        """Detect password input fields."""
        password_fields = await evaluate(
            """
            () => {
                const fields = Array.from(document.querySelectorAll('input[type="password"]'));
                return fields.map((field, idx) => ({
                    index: idx,
                    id: field.id || null,
                    name: field.name || null,
                    placeholder: field.placeholder || null,
                    autocomplete: field.autocomplete || null,
                    required: field.required,
                    visible: field.offsetParent !== null
                }));
            }
        """
        )
        return password_fields if password_fields else []

    async def _detect_hidden_inputs(self, evaluate: Callable) -> List[Dict[str, Any]]:
        """Detect hidden input fields."""
        hidden_inputs = await evaluate(
            """
            () => {
                const fields = Array.from(document.querySelectorAll('input[type="hidden"]'));
                return fields.map((field, idx) => ({
                    index: idx,
                    name: field.name || null,
                    value: field.value || null,
                    id: field.id || null
                }));
            }
        """
        )
        return hidden_inputs if hidden_inputs else []

    async def _detect_iframes(self, evaluate: Callable) -> List[Dict[str, Any]]:
        """Detect iframes (potential for clickjacking)."""
        iframes = await evaluate(
            """
            () => {
                const frames = Array.from(document.querySelectorAll('iframe'));
                return frames.map((frame, idx) => ({
                    index: idx,
                    src: frame.src || null,
                    width: frame.width || null,
                    height: frame.height || null,
                    sandbox: frame.sandbox ? frame.sandbox.value : null,
                    hidden: frame.style.display === 'none' || frame.style.visibility === 'hidden'
                }));
            }
        """
        )
        return iframes if iframes else []

    async def _detect_overlays(self, evaluate: Callable) -> List[Dict[str, Any]]:
        """Detect suspicious overlays or modals."""
        overlays = await evaluate(
            """
            () => {
                const elements = Array.from(document.querySelectorAll('div, section'));
                const overlays = elements.filter(el => {
                    const style = window.getComputedStyle(el);
                    return (
                        (style.position === 'fixed' || style.position === 'absolute') &&
                        (parseInt(style.zIndex) > 1000 || style.zIndex === 'auto') &&
                        (parseInt(style.width) > 300 || parseInt(style.height) > 300)
                    );
                });
                return overlays.map((el, idx) => ({
                    index: idx,
                    id: el.id || null,
                    class: el.className || null,
                    position: window.getComputedStyle(el).position,
                    zIndex: window.getComputedStyle(el).zIndex,
                    has_form: el.querySelector('form') !== null
                }));
            }
        """
        )
        return overlays if overlays else []

    def _generate_evidence(self, findings: Dict[str, Any]) -> List[str]:
        """Generate human-readable evidence from findings."""
        evidence = []

        if findings["forms_count"] > 0:
            evidence.append(f"Found {findings['forms_count']} form(s) on the page")

            for form in findings.get("forms", []):
                if form["has_password"]:
                    action = form["action"]
                    if action and action != "none":
                        evidence.append(f"Form submits credentials to: {action}")
                    else:
                        evidence.append(
                            "Form with password field has no action "
                            "(likely JavaScript-based submission)"
                        )

        if findings["password_fields"]:
            evidence.append(f"Detected {len(findings['password_fields'])} password input field(s)")

        if findings["hidden_inputs"]:
            evidence.append(f"Found {len(findings['hidden_inputs'])} hidden input field(s)")

        if findings["suspicious_iframes"]:
            evidence.append(
                f"Detected {len(findings['suspicious_iframes'])} iframe(s) - "
                "potential clickjacking risk"
            )

        if findings["overlays"]:
            evidence.append(
                f"Found {len(findings['overlays'])} overlay element(s) - "
                "may be used to hide legitimate content"
            )

        return evidence
