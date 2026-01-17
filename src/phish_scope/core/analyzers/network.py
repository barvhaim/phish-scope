"""
Network Analyzer - Analyzes network traffic for data exfiltration.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from phish_scope.core.analyzers import BaseAnalyzer


logger = logging.getLogger(__name__)


class NetworkAnalyzer(BaseAnalyzer):
    """
    Analyzes network traffic for phishing indicators:
    - POST requests with form data
    - Suspicious exfiltration endpoints
    - Third-party data sharing
    - Credential transmission patterns
    """

    # Suspicious TLDs and patterns
    SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"]
    LEGITIMATE_DOMAINS = [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "facebook.com",
        "fbcdn.net",
        "cloudflare.com",
        "cloudflareinsights.com",
        "microsoft.com",
        "live.com",
        "amazon.com",
        "amazonaws.com",
        "jquery.com",
        "jsdelivr.net",
        "cdnjs.cloudflare.com",
    ]

    def __init__(self):
        super().__init__(name="network_analyzer")

    async def analyze(
        self,
        page=None,
        browser_loader=None,
        network_log: Optional[List[Dict[str, Any]]] = None,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Analyze network traffic for exfiltration patterns.

        Args:
            page: Not used by this analyzer
            browser_loader: Not used by this analyzer
            network_log: List of network requests/responses
            output_dir: Directory to save artifacts

        Returns:
            Dictionary containing network analysis findings
        """
        findings = {
            "total_requests": 0,
            "post_requests": [],
            "exfiltration_candidates": [],
            "third_party_domains": [],
            "suspicious_endpoints": [],
            "evidence": [],
        }

        if not network_log:
            logger.warning("No network log provided")
            return findings

        try:
            # Filter requests only
            requests = [entry for entry in network_log if entry.get("type") == "request"]
            findings["total_requests"] = len(requests)

            # Analyze POST requests
            post_requests = self._analyze_post_requests(requests)
            findings["post_requests"] = post_requests

            # Identify exfiltration candidates
            exfil_candidates = self._identify_exfiltration(requests)
            findings["exfiltration_candidates"] = exfil_candidates

            # Identify third-party domains
            third_party = self._identify_third_party_domains(requests)
            findings["third_party_domains"] = third_party

            # Identify suspicious endpoints
            suspicious = self._identify_suspicious_endpoints(requests)
            findings["suspicious_endpoints"] = suspicious

            # Save network log
            if output_dir:
                artifacts_dir = output_dir / "artifacts"
                artifacts_dir.mkdir(exist_ok=True, parents=True)

                network_log_path = artifacts_dir / "network_log.json"
                with open(network_log_path, "w", encoding="utf-8") as f:
                    json.dump(network_log, f, indent=2)

                # Save exfiltration candidates
                if exfil_candidates:
                    exfil_path = artifacts_dir / "exfiltration_candidates.json"
                    with open(exfil_path, "w", encoding="utf-8") as f:
                        json.dump(exfil_candidates, f, indent=2)

            # Generate evidence
            findings["evidence"] = self._generate_evidence(findings)

            logger.info(
                f"Network analysis complete: {len(exfil_candidates)} exfiltration candidates found"
            )

        except Exception as e:
            logger.error(f"Network analysis failed: {str(e)}")
            findings["error"] = str(e)

        return findings

    def _analyze_post_requests(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze POST requests."""
        post_requests = []

        for req in requests:
            if req.get("method") == "POST":
                parsed = urlparse(req["url"])
                post_requests.append(
                    {
                        "url": req["url"],
                        "domain": parsed.netloc,
                        "path": parsed.path,
                        "headers": req.get("headers", {}),
                        "resource_type": req.get("resource_type"),
                    }
                )

        return post_requests

    def _identify_exfiltration(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential data exfiltration endpoints."""
        candidates = []

        for req in requests:
            if req.get("method") != "POST":
                continue

            url = req["url"]
            parsed = urlparse(url)
            domain = parsed.netloc

            # Skip legitimate domains
            if any(legit in domain for legit in self.LEGITIMATE_DOMAINS):
                continue

            # Check for suspicious patterns
            suspicious_score = 0
            reasons = []

            # Suspicious TLD
            if any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                suspicious_score += 2
                reasons.append("Suspicious TLD")

            # Suspicious path patterns
            suspicious_paths = ["/api/", "/submit", "/login", "/auth", "/verify", "/process"]
            if any(pattern in parsed.path.lower() for pattern in suspicious_paths):
                suspicious_score += 1
                reasons.append("Suspicious endpoint path")

            # Check for data-related parameters
            if any(keyword in url.lower() for keyword in ["data", "user", "cred", "pass", "login"]):
                suspicious_score += 1
                reasons.append("Data-related URL parameters")

            # IP address instead of domain
            if self._is_ip_address(domain):
                suspicious_score += 2
                reasons.append("Direct IP address (not domain)")

            # Non-standard port
            if ":" in domain and not domain.endswith(":443") and not domain.endswith(":80"):
                suspicious_score += 1
                reasons.append("Non-standard port")

            if suspicious_score > 0:
                candidates.append(
                    {
                        "url": url,
                        "domain": domain,
                        "path": parsed.path,
                        "suspicious_score": suspicious_score,
                        "reasons": reasons,
                        "method": req.get("method"),
                        "resource_type": req.get("resource_type"),
                    }
                )

        # Sort by suspicious score
        candidates.sort(key=lambda x: x["suspicious_score"], reverse=True)
        return candidates

    def _identify_third_party_domains(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify third-party domains."""
        if not requests:
            return []

        # Get the main domain from the first request (usually the page itself)
        main_domain = urlparse(requests[0]["url"]).netloc
        third_party: Dict[str, Dict[str, Any]] = {}

        for req in requests:
            domain = urlparse(req["url"]).netloc
            if domain != main_domain and domain not in third_party:
                third_party[domain] = {
                    "domain": domain,
                    "request_count": 0,
                    "methods": set(),
                    "resource_types": set(),
                }

            if domain != main_domain:
                third_party[domain]["request_count"] += 1
                third_party[domain]["methods"].add(req.get("method", "GET"))
                third_party[domain]["resource_types"].add(req.get("resource_type", "unknown"))

        # Convert sets to lists for JSON serialization
        result = []
        for domain_info in third_party.values():
            domain_info["methods"] = list(domain_info["methods"])
            domain_info["resource_types"] = list(domain_info["resource_types"])
            result.append(domain_info)

        return result

    def _identify_suspicious_endpoints(
        self, requests: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify suspicious API endpoints."""
        suspicious = []

        suspicious_keywords = [
            "telegram",
            "discord",
            "webhook",
            "bot",
            "pastebin",
            "hastebin",
            "paste",
            "logger",
            "log",
            "track",
            "steal",
            "grab",
            "collect",
        ]

        for req in requests:
            url = req["url"].lower()
            domain = urlparse(req["url"]).netloc.lower()

            for keyword in suspicious_keywords:
                if keyword in url or keyword in domain:
                    suspicious.append(
                        {
                            "url": req["url"],
                            "domain": domain,
                            "keyword": keyword,
                            "method": req.get("method"),
                            "reason": f"Contains suspicious keyword: {keyword}",
                        }
                    )
                    break

        return suspicious

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        # Remove port if present
        domain = domain.split(":")[0]
        parts = domain.split(".")
        if len(parts) == 4:
            return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        return False

    def _generate_evidence(self, findings: Dict[str, Any]) -> List[str]:
        """Generate human-readable evidence from findings."""
        evidence = []

        if findings["total_requests"] > 0:
            evidence.append(f"Page made {findings['total_requests']} network request(s)")

        if findings["post_requests"]:
            evidence.append(
                f"Detected {len(findings['post_requests'])} POST request(s) - "
                "potential data submission"
            )

        if findings["exfiltration_candidates"]:
            evidence.append(
                f"Identified {len(findings['exfiltration_candidates'])} "
                "potential data exfiltration endpoint(s)"
            )

            # Highlight top candidate
            top_candidate = findings["exfiltration_candidates"][0]
            evidence.append(
                f"Most suspicious endpoint: {top_candidate['domain']} "
                f"(score: {top_candidate['suspicious_score']}, "
                f"reasons: {', '.join(top_candidate['reasons'])})"
            )

        if findings["third_party_domains"]:
            evidence.append(
                f"Page communicates with {len(findings['third_party_domains'])} "
                "third-party domain(s)"
            )

        if findings["suspicious_endpoints"]:
            evidence.append(
                f"Detected {len(findings['suspicious_endpoints'])} request(s) to "
                "suspicious endpoints (e.g., Telegram, Discord webhooks, paste sites)"
            )

        return evidence
