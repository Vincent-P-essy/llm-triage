"""Tests for app.analyzer.LLMAnalyzer using mocked LLM clients."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from app.analyzer import LLMAnalyzer, _parse_json_response

MOCK_INCIDENT = {
    "id": "INC-001",
    "title": "SQL Injection attempt",
    "description": "Anomalous SQL payload detected in login form.",
    "source_ip": "10.10.0.5",
    "severity": "HIGH",
    "status": "open",
    "created_at": "2024-05-01T10:00:00Z",
}

CLASSIFY_RESPONSE = json.dumps({
    "severity": "HIGH",
    "confidence": 0.88,
    "reasoning": "SQL injection targeting authentication endpoint.",
    "tags": ["sql-injection", "authentication"],
})

SUGGEST_RESPONSE = json.dumps({
    "priority_score": 8,
    "immediate_actions": ["Block source IP", "Alert DBA team"],
    "investigation_steps": [
        "Review web application firewall logs",
        "Check database audit logs for successful queries",
        "Inspect application logs around the timestamp",
    ],
    "escalate_to": "SOC L2",
    "estimated_resolution_hours": 4,
})


@pytest.fixture
def mock_anthropic_client():
    with patch("anthropic.Anthropic") as mock_cls:
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        yield mock_instance


def _make_anthropic_response(text: str):
    content_block = MagicMock()
    content_block.text = text
    response = MagicMock()
    response.content = [content_block]
    return response


def test_analyze_anthropic_returns_parsed_dict(mock_anthropic_client):
    mock_anthropic_client.messages.create.return_value = _make_anthropic_response(
        CLASSIFY_RESPONSE
    )
    with patch("os.getenv", return_value="anthropic"):
        analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
        analyzer.provider = "anthropic"
        analyzer._client = mock_anthropic_client

    with patch.dict(os.environ, {"ANTHROPIC_MODEL": "test-model"}):
        result = analyzer.analyze(MOCK_INCIDENT, "classify prompt")
    assert result["severity"] == "HIGH"
    assert result["confidence"] == 0.88
    assert "sql-injection" in result["tags"]


def test_suggest_anthropic_returns_parsed_dict(mock_anthropic_client):
    mock_anthropic_client.messages.create.return_value = _make_anthropic_response(
        SUGGEST_RESPONSE
    )
    analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
    analyzer.provider = "anthropic"
    analyzer._client = mock_anthropic_client

    classification = {"severity": "HIGH"}
    with patch.dict(os.environ, {"ANTHROPIC_MODEL": "test-model"}):
        result = analyzer.suggest(MOCK_INCIDENT, classification, "suggest prompt")
    assert result["priority_score"] == 8
    assert result["escalate_to"] == "SOC L2"
    assert len(result["immediate_actions"]) == 2


def test_analyze_invalid_json_returns_fallback(mock_anthropic_client):
    mock_anthropic_client.messages.create.return_value = _make_anthropic_response(
        "I cannot determine the severity of this incident."
    )
    analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
    analyzer.provider = "anthropic"
    analyzer._client = mock_anthropic_client

    with patch.dict(os.environ, {"ANTHROPIC_MODEL": "test-model"}):
        result = analyzer.analyze(MOCK_INCIDENT, "classify prompt")
    assert result["severity"] == "UNKNOWN"
    assert result["confidence"] == 0.0


def test_parse_json_response_direct():
    data = {"severity": "LOW", "confidence": 0.5, "reasoning": "Low risk", "tags": []}
    assert _parse_json_response(json.dumps(data)) == data


def test_parse_json_response_with_surrounding_text():
    text = 'Here is the JSON:\n{"severity": "HIGH"}\nDone.'
    result = _parse_json_response(text)
    assert result["severity"] == "HIGH"


def test_parse_json_response_raises_on_garbage():
    with pytest.raises(ValueError):
        _parse_json_response("not json at all")


def test_openai_analyze():
    mock_openai = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = CLASSIFY_RESPONSE
    mock_openai.chat.completions.create.return_value = MagicMock(choices=[mock_choice])

    analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
    analyzer.provider = "openai"
    analyzer._client = mock_openai

    result = analyzer.analyze(MOCK_INCIDENT, "classify prompt")
    assert result["severity"] == "HIGH"


def test_mock_analyze_returns_deterministic_classification():
    analyzer = LLMAnalyzer(provider="mock")

    result = analyzer.analyze(MOCK_INCIDENT, "classify prompt")

    assert result["severity"] == "HIGH"
    assert result["confidence"] > 0
    assert "sql-injection" in result["tags"]


def test_mock_suggest_returns_deterministic_actions():
    analyzer = LLMAnalyzer(provider="mock")

    result = analyzer.suggest(MOCK_INCIDENT, {"severity": "HIGH"}, "suggest prompt")

    assert result["priority_score"] == 8
    assert result["escalate_to"] == "SOC L2"
    assert "10.10.0.5" in result["immediate_actions"][0]
