"""Tests for app.reporter.IncidentReporter using mocked HTTP."""

import responses as responses_lib
import pytest
from app.reporter import IncidentReporter

BASE_URL = "http://mock-tracker:5000"

MOCK_INCIDENT = {
    "id": "INC-003",
    "title": "Ransomware beacon detected",
    "description": "C2 communication pattern matched known ransomware.",
    "source_ip": "172.16.0.99",
    "severity": "CRITICAL",
    "status": "open",
    "created_at": "2024-05-02T08:30:00Z",
}

MOCK_CLASSIFICATION = {
    "severity": "CRITICAL",
    "confidence": 0.97,
    "reasoning": "C2 traffic matches Ryuk ransomware IOC.",
    "tags": ["ransomware", "c2", "lateral-movement"],
}

MOCK_SUGGESTION = {
    "priority_score": 10,
    "immediate_actions": ["Isolate host", "Notify CISO"],
    "investigation_steps": [
        "Capture memory dump of affected host",
        "Check EDR for process tree",
        "Identify lateral movement targets",
    ],
    "escalate_to": "CISO",
    "estimated_resolution_hours": 48,
}


@pytest.fixture
def reporter():
    return IncidentReporter(base_url=BASE_URL)


def test_enrich_and_update_dry_run_no_http(reporter):
    """In dry-run mode, no HTTP request should be made."""
    enriched = reporter.enrich_and_update(
        MOCK_INCIDENT, MOCK_CLASSIFICATION, MOCK_SUGGESTION, dry_run=True
    )
    assert enriched["llm_severity"] == "CRITICAL"
    assert enriched["llm_priority_score"] == 10
    assert enriched["llm_escalate_to"] == "CISO"
    assert "llm_analyzed_at" in enriched


@responses_lib.activate
def test_enrich_and_update_patches_api(reporter):
    responses_lib.add(
        responses_lib.PATCH,
        f"{BASE_URL}/api/incidents/INC-003",
        json={"status": "updated"},
        status=200,
    )
    enriched = reporter.enrich_and_update(
        MOCK_INCIDENT, MOCK_CLASSIFICATION, MOCK_SUGGESTION, dry_run=False
    )
    assert enriched["llm_severity"] == "CRITICAL"
    assert len(responses_lib.calls) == 1
    assert responses_lib.calls[0].request.method == "PATCH"


@responses_lib.activate
def test_enrich_and_update_handles_api_error(reporter):
    responses_lib.add(
        responses_lib.PATCH,
        f"{BASE_URL}/api/incidents/INC-003",
        status=500,
    )
    # Should not raise, just log
    enriched = reporter.enrich_and_update(
        MOCK_INCIDENT, MOCK_CLASSIFICATION, MOCK_SUGGESTION, dry_run=False
    )
    assert enriched["llm_severity"] == "CRITICAL"


def test_generate_report_empty(reporter):
    report = reporter.generate_report([])
    assert report["total_incidents"] == 0
    assert report["severity_breakdown"] == {}
    assert report["average_priority_score"] is None


def test_generate_report_with_data(reporter):
    enriched1 = {
        **MOCK_INCIDENT,
        "llm_severity": "CRITICAL",
        "llm_priority_score": 10,
        "llm_escalate_to": "CISO",
    }
    enriched2 = {
        **MOCK_INCIDENT,
        "id": "INC-004",
        "llm_severity": "HIGH",
        "llm_priority_score": 7,
        "llm_escalate_to": "SOC L2",
    }
    report = reporter.generate_report([enriched1, enriched2])
    assert report["total_incidents"] == 2
    assert report["severity_breakdown"]["CRITICAL"] == 1
    assert report["severity_breakdown"]["HIGH"] == 1
    assert report["average_priority_score"] == 8.5
    assert report["escalation_breakdown"]["CISO"] == 1
