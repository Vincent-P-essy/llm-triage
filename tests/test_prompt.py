"""Tests for app.prompt.PromptBuilder."""

import pytest
from app.prompt import PromptBuilder

MOCK_INCIDENT = {
    "id": "INC-001",
    "title": "Brute-force login attempt",
    "description": "500 failed SSH login attempts in 60 seconds from a single IP.",
    "source_ip": "192.168.1.42",
    "severity": "HIGH",
    "status": "open",
    "created_at": "2024-05-01T10:00:00Z",
}

MOCK_CLASSIFICATION = {
    "severity": "HIGH",
    "confidence": 0.92,
    "reasoning": "High volume brute-force indicates credential stuffing.",
    "tags": ["brute-force", "credential-theft"],
}


@pytest.fixture
def builder():
    return PromptBuilder()


def test_build_classify_prompt_contains_title(builder):
    prompt = builder.build_classify_prompt(MOCK_INCIDENT)
    assert "Brute-force login attempt" in prompt


def test_build_classify_prompt_contains_source_ip(builder):
    prompt = builder.build_classify_prompt(MOCK_INCIDENT)
    assert "192.168.1.42" in prompt


def test_build_classify_prompt_contains_created_at(builder):
    prompt = builder.build_classify_prompt(MOCK_INCIDENT)
    assert "2024-05-01T10:00:00Z" in prompt


def test_build_classify_prompt_contains_instructions(builder):
    prompt = builder.build_classify_prompt(MOCK_INCIDENT)
    assert "severity" in prompt.lower()
    assert "JSON" in prompt


def test_build_suggest_prompt_contains_severity(builder):
    prompt = builder.build_suggest_prompt(MOCK_INCIDENT, MOCK_CLASSIFICATION)
    assert "HIGH" in prompt


def test_build_suggest_prompt_contains_title(builder):
    prompt = builder.build_suggest_prompt(MOCK_INCIDENT, MOCK_CLASSIFICATION)
    assert "Brute-force login attempt" in prompt


def test_build_suggest_prompt_contains_source_ip(builder):
    prompt = builder.build_suggest_prompt(MOCK_INCIDENT, MOCK_CLASSIFICATION)
    assert "192.168.1.42" in prompt


def test_build_classify_prompt_missing_field_does_not_crash(builder):
    """Jinja2 should handle missing optional fields without raising."""
    minimal = {
        "id": "INC-002",
        "title": "Test",
        "description": "desc",
        "source_ip": "10.0.0.1",
        "created_at": "2024-01-01T00:00:00Z",
    }
    prompt = builder.build_classify_prompt(minimal)
    assert "Test" in prompt
