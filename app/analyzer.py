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
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")
        logger.debug("Initialized LLM client for provider: %s", self.provider)

    def _call_llm(self, prompt: str) -> str:
        """Send a prompt to the configured LLM and return the response text."""
        if self.provider == "anthropic":
            def _do():
                response = self._client.messages.create(
                    model="claude-sonnet-4-6",
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
