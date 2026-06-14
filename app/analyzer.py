"""LLM API integration for incident analysis."""

import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")
MAX_RETRIES = 3
BACKOFF_BASE = 2.0


def _parse_json_response(text: str) -> dict:
    """Extract and parse JSON from LLM response text."""
    text = text.strip()
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to extract JSON block
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Could not parse JSON from LLM response: {text[:200]}")


def _retry(fn, retries: int = MAX_RETRIES, backoff: float = BACKOFF_BASE):
    """Call fn with exponential backoff retry."""
    for attempt in range(retries):
        try:
            return fn()
        except Exception as exc:
            if attempt == retries - 1:
                raise
            wait = backoff ** attempt
            logger.warning(
                "Attempt %d/%d failed: %s. Retrying in %.1fs...",
                attempt + 1,
                retries,
                exc,
                wait,
            )
            time.sleep(wait)


class LLMAnalyzer:
    """Analyzes security incidents using an LLM provider."""

    def __init__(self, provider: str = LLM_PROVIDER) -> None:
        self.provider = provider.lower()
        self._client: Any = None
        self._init_client()

    def _init_client(self) -> None:
        if self.provider == "anthropic":
            import anthropic  # noqa: PLC0415

            self._client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        elif self.provider == "openai":
            import openai  # noqa: PLC0415

            self._client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        elif self.provider == "mock":
            self._client = None
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")
        logger.debug("Initialized LLM client for provider: %s", self.provider)

    def _mock_analyze(self, incident: dict) -> dict:
        """Return deterministic local analysis for demos without an LLM API key."""
        text = " ".join(
            str(incident.get(key, ""))
            for key in ("title", "description", "severity")
        ).lower()
        tags = []

        critical_keywords = (
            "ransomware",
            "exfiltration",
            "data breach",
            "credential theft",
            "lateral movement",
            "domain admin",
            "payment",
            "wire transfer",
            "pci",
        )
        high_keywords = (
            "sql injection",
            "sqli",
            "brute force",
            "suspicious login",
            "tor",
            "malware",
            "privilege escalation",
        )
        medium_keywords = ("phishing", "anomaly", "suspicious", "failed login")

        if any(keyword in text for keyword in critical_keywords):
            severity = "CRITICAL"
            confidence = 0.78
            reasoning = "Mock mode detected banking-critical risk indicators."
        elif any(keyword in text for keyword in high_keywords):
            severity = "HIGH"
            confidence = 0.72
            reasoning = "Mock mode detected high-risk security indicators."
        elif any(keyword in text for keyword in medium_keywords):
            severity = "MEDIUM"
            confidence = 0.66
            reasoning = "Mock mode detected suspicious activity requiring review."
        else:
            severity = "LOW"
            confidence = 0.58
            reasoning = "Mock mode found no obvious high-risk indicators."

        tag_keywords = {
            "sql-injection": ("sql injection", "sqli"),
            "credential-access": ("credential", "login", "brute force"),
            "malware": ("malware", "ransomware"),
            "data-exfiltration": ("exfiltration", "data breach"),
            "payment-risk": ("payment", "wire transfer", "pci"),
        }
        for tag, keywords in tag_keywords.items():
            if any(keyword in text for keyword in keywords):
                tags.append(tag)

        return {
            "severity": severity,
            "confidence": confidence,
            "reasoning": reasoning,
            "tags": tags,
        }

    def _mock_suggest(self, incident: dict, classification: dict) -> dict:
        """Return deterministic local suggestions for demos without an LLM API key."""
        severity = classification.get("severity", "LOW")
        priority_by_severity = {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 2,
        }
        escalation_by_severity = {
            "CRITICAL": "CISO",
            "HIGH": "SOC L2",
            "MEDIUM": "SOC L1",
            "LOW": "SOC L1",
        }
        hours_by_severity = {
            "CRITICAL": 2,
            "HIGH": 4,
            "MEDIUM": 12,
            "LOW": 24,
        }

        source_ip = incident.get("source_ip")
        immediate_actions = [
            "Preserve relevant logs and alert context",
            "Review affected account and host activity",
        ]
        if source_ip:
            immediate_actions.insert(0, f"Review or temporarily block source IP {source_ip}")

        if severity in {"CRITICAL", "HIGH"}:
            immediate_actions.append("Escalate to the on-call incident responder")

        return {
            "priority_score": priority_by_severity.get(severity, 3),
            "immediate_actions": immediate_actions,
            "investigation_steps": [
                "Correlate authentication, endpoint, network, and application logs",
                "Check for similar activity across recent open incidents",
                "Document affected assets, users, and containment decisions",
            ],
            "escalate_to": escalation_by_severity.get(severity, "SOC L1"),
            "estimated_resolution_hours": hours_by_severity.get(severity, 24),
        }

    def _call_llm(self, prompt: str) -> str:
        """Send a prompt to the configured LLM and return the response text."""
        if self.provider == "anthropic":
            def _do():
                model = os.getenv("ANTHROPIC_MODEL")
                if not model:
                    raise ValueError(
                        "ANTHROPIC_MODEL is required when LLM_PROVIDER=anthropic"
                    )
                response = self._client.messages.create(
                    model=model,
                    max_tokens=512,
                    messages=[{"role": "user", "content": prompt}],
                )
                return response.content[0].text

            return _retry(_do)

        elif self.provider == "openai":
            def _do():
                response = self._client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=512,
                )
                return response.choices[0].message.content

            return _retry(_do)

        raise RuntimeError(f"No call logic for provider: {self.provider}")

    def analyze(self, incident: dict, prompt: str) -> dict:
        """Classify incident severity using the classify prompt.

        Args:
            incident: Raw incident dict (used for logging).
            prompt: Pre-rendered classify prompt string.

        Returns:
            Parsed JSON dict with severity, confidence, reasoning, tags.
        """
        if self.provider == "mock":
            logger.info("Classifying incident %s via mock provider", incident.get("id"))
            return self._mock_analyze(incident)

        logger.info("Classifying incident %s via %s", incident.get("id"), self.provider)
        raw = self._call_llm(prompt)
        try:
            result = _parse_json_response(raw)
        except ValueError as exc:
            logger.error("JSON parse error in classify response: %s", exc)
            result = {
                "severity": "UNKNOWN",
                "confidence": 0.0,
                "reasoning": "Failed to parse LLM response",
                "tags": [],
            }
        return result

    def suggest(self, incident: dict, classification: dict, prompt: str) -> dict:
        """Generate investigation steps using the suggest prompt.

        Args:
            incident: Raw incident dict (used for logging).
            classification: Output of analyze().
            prompt: Pre-rendered suggest prompt string.

        Returns:
            Parsed JSON dict with priority_score, immediate_actions,
            investigation_steps, escalate_to, estimated_resolution_hours.
        """
        if self.provider == "mock":
            logger.info(
                "Generating mock suggestions for incident %s (%s severity)",
                incident.get("id"),
                classification.get("severity"),
            )
            return self._mock_suggest(incident, classification)

        logger.info(
            "Generating suggestions for incident %s (%s severity)",
            incident.get("id"),
            classification.get("severity"),
        )
        raw = self._call_llm(prompt)
        try:
            result = _parse_json_response(raw)
        except ValueError as exc:
            logger.error("JSON parse error in suggest response: %s", exc)
            result = {
                "priority_score": 5,
                "immediate_actions": ["Manual review required"],
                "investigation_steps": ["Review incident details manually"],
                "escalate_to": "SOC L1",
                "estimated_resolution_hours": 24,
            }
        return result
