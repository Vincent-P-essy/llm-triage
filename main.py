#!/usr/bin/env python3
"""Entry point for llm-triage: LLM-assisted security incident triage."""

import argparse
import json
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from app.analyzer import LLMAnalyzer
from app.ingest import IncidentClient
from app.prompt import PromptBuilder
from app.reporter import IncidentReporter


def setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="llm-triage: LLM-assisted security incident triage",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Classify and suggest without updating the incident API.",
    )
    parser.add_argument(
        "--incident-id",
        metavar="ID",
        help="Process a single incident by ID instead of all open incidents.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a summary report after processing.",
    )
    return parser.parse_args()


def process_incident(
    incident: dict,
    analyzer: LLMAnalyzer,
    builder: PromptBuilder,
    reporter: IncidentReporter,
    dry_run: bool,
) -> dict:
    """Run the full triage pipeline for a single incident."""
    logger = logging.getLogger(__name__)
    logger.info("Processing incident %s: %s", incident.get("id"), incident.get("title"))

    classify_prompt = builder.build_classify_prompt(incident)
    classification = analyzer.analyze(incident, classify_prompt)
    logger.info(
        "Classification for %s: %s (confidence=%.2f)",
        incident.get("id"),
        classification.get("severity"),
        classification.get("confidence", 0.0),
    )

    suggest_prompt = builder.build_suggest_prompt(incident, classification)
    suggestion = analyzer.suggest(incident, classification, suggest_prompt)
    logger.info(
        "Suggestion for %s: priority=%s, escalate_to=%s",
        incident.get("id"),
        suggestion.get("priority_score"),
        suggestion.get("escalate_to"),
    )

    enriched = reporter.enrich_and_update(incident, classification, suggestion, dry_run=dry_run)
    return enriched


def main() -> int:
    setup_logging()
    args = parse_args()
    logger = logging.getLogger(__name__)

    client = IncidentClient()
    builder = PromptBuilder()
    analyzer = LLMAnalyzer()
    reporter = IncidentReporter()

    if args.incident_id:
        incident = client.get_incident(args.incident_id)
        if incident is None:
            logger.error("Incident %s not found or API unreachable.", args.incident_id)
            return 1
        incidents = [incident]
    else:
        incidents = client.get_open_incidents()
        if not incidents:
            logger.warning("No open incidents found. Exiting.")
            return 0

    logger.info("Starting triage for %d incident(s).", len(incidents))
    enriched_list = []
    for incident in incidents:
        try:
            enriched = process_incident(incident, analyzer, builder, reporter, args.dry_run)
            enriched_list.append(enriched)
        except Exception as exc:
            logger.error(
                "Unhandled error processing incident %s: %s", incident.get("id"), exc
            )

    if args.report:
        report = reporter.generate_report(enriched_list)
        print(json.dumps(report, indent=2))

    logger.info("Triage complete. Processed %d incident(s).", len(enriched_list))
    return 0


if __name__ == "__main__":
    sys.exit(main())
