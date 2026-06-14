"""Incident ingestion from the incident-tracker-api."""

import logging
import os
from typing import Optional

import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

logger = logging.getLogger(__name__)

INCIDENT_TRACKER_URL = os.getenv("INCIDENT_TRACKER_URL", "http://localhost:5000")


class IncidentClient:
    """Client for reading incidents from the incident-tracker-api."""

    def __init__(self, base_url: Optional[str] = None) -> None:
        self.base_url = (base_url or INCIDENT_TRACKER_URL).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def get_open_incidents(self) -> list[dict]:
        """Fetch all open incidents from the API.

        Returns:
            List of incident dicts with keys: id, title, description,
            source_ip, severity, status, created_at.
        """
        url = f"{self.base_url}/api/incidents"
        try:
            response = self.session.get(url, params={"status": "open"}, timeout=10)
            response.raise_for_status()
            incidents = response.json()
            logger.info("Fetched %d open incidents", len(incidents))
            return incidents
        except ConnectionError:
            logger.warning(
                "Cannot connect to incident tracker at %s. Returning empty list.",
                self.base_url,
            )
            return []
        except Timeout:
            logger.warning("Request to %s timed out. Returning empty list.", url)
            return []
        except RequestException as exc:
            logger.warning("HTTP error fetching incidents: %s. Returning empty list.", exc)
            return []

    def get_incident(self, incident_id: str) -> Optional[dict]:
        """Fetch a single incident by ID."""
        url = f"{self.base_url}/api/incidents/{incident_id}"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except ConnectionError:
            logger.warning("Cannot connect to incident tracker at %s.", self.base_url)
            return None
        except Timeout:
            logger.warning("Request to %s timed out.", url)
            return None
        except RequestException as exc:
            logger.warning("HTTP error fetching incident %s: %s.", incident_id, exc)
            return None
