"""Structured prompt templates using Jinja2."""

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


class PromptBuilder:
    """Builds LLM prompts from Jinja2 templates."""

    def __init__(self, prompts_dir: Path = PROMPTS_DIR) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(prompts_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def build_classify_prompt(self, incident: dict) -> str:
        """Build the severity classification prompt for an incident.

        Args:
            incident: Incident dict with keys id, title, description,
                      source_ip, severity, status, created_at.

        Returns:
            Rendered prompt string.
        """
        try:
            template = self.env.get_template("classify.txt")
        except TemplateNotFound:
            raise FileNotFoundError("prompts/classify.txt not found")
        return template.render(**incident)

    def build_suggest_prompt(self, incident: dict, classification: dict) -> str:
        """Build the investigation steps prompt.

        Args:
            incident: Raw incident dict.
            classification: Output from LLMAnalyzer.analyze(), containing
                            at least 'severity'.

        Returns:
            Rendered prompt string.
        """
        try:
            template = self.env.get_template("suggest.txt")
        except TemplateNotFound:
            raise FileNotFoundError("prompts/suggest.txt not found")
        context = {**incident, **classification}
        return template.render(**context)
