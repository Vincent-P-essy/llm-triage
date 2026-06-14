"""Incident enrichment and API update."""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

INCIDENT_TRACKER_URL = os.getenv("INCIDENT_TRACKER_URL", "http://localhost:5000")


class IncidentReporter:
    """Enriches incidents with LLM analysis and pushes updates to the API."""

    def __init__(self, base_url: Optional[str] = None) -> None:
        self.base_url = (base_url or INCIDENT_TRACKER_URL).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def enrich_and_update(
        self,
        incident: dict,
        classification: dict,
        suggestion: dict,
        dry_run: bool = False,
    ) -> dict:
        """Build enriched incident and PATCH it back to the API.

        Args:
            incident: Original incident dict.
            classification: Output of LLMAnalyzer.analyze().
            suggestion: Output of LLMAnalyzer.suggest().
            dry_run: If True, skip the PATCH call.

        Returns:
            Enriched incident dict.
        """
        enriched = {
            **incident,
            "llm_severity": classification.get("severity"),
            "llm_confidence": classification.get("confidence"),
            "llm_reasoning": classification.get("reasoning"),
            "llm_tags": classification.get("tags", []),
            "llm_priority_score": suggestion.get("priority_score"),
            "llm_immediate_actions": suggestion.get("immediate_actions", []),
            "llm_investigation_steps": suggestion.get("investigation_steps", []),
            "llm_escalate_to": suggestion.get("escalate_to"),
            "llm_estimated_resolution_hours": suggestion.get("estimated_resolution_hours"),
            "llm_analyzed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

        if dry_run:
            logger.info("[dry-run] Would PATCH incident %s with enriched data.", incident.get("id"))
            return enriched

        incident_id = incident.get("id")
        url = f"{self.base_url}/api/incidents/{incident_id}"
        payload = {k: v for k, v in enriched.items() if k.startswith("llm_")}

        try:
            response = self.session.patch(url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Successfully updated incident %s.", incident_id)
        except RequestException as exc:
            logger.error("Failed to update incident %s: %s", incident_id, exc)

        return enriched

    def generate_report(self, incidents: list[dict]) -> dict:
        """Generate summary statistics across a batch of enriched incidents.

        Args:
            incidents: List of enriched incident dicts (output of enrich_and_update).

        Returns:
            Summary dict with counts and averages.
        """
        total = len(incidents)
        severity_counts: dict[str, int] = {}
        priority_scores = []
        escalations: dict[str, int] = {}

        for inc in incidents:
            sev = inc.get("llm_severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            score = inc.get("llm_priority_score")
            if score is not None:
                priority_scores.append(score)

            esc = inc.get("llm_escalate_to", "None")
            escalations[esc] = escalations.get(esc, 0) + 1

        return {
            "total_incidents": total,
            "severity_breakdown": severity_counts,
            "average_priority_score": (
                round(sum(priority_scores) / len(priority_scores), 2)
                if priority_scores
                else None
            ),
            "escalation_breakdown": escalations,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }
