"""
NLP processing tasks
"""

from celery import current_app as celery_app
from app.nlp.summarizer import ThreatSummarizer
from app.nlp.entity_extractor import EntityExtractor
import logging

logger = logging.getLogger(__name__)


@celery_app.task
def generate_threat_summary(threat_id: int):
    """Generate AI summary for a threat"""
    try:
        summarizer = ThreatSummarizer()
        result = summarizer.summarize_threat(threat_id)
        logger.info(f"Summary generated for threat {threat_id}")
        return result
    except Exception as exc:
        logger.error(f"Summary generation failed for {threat_id}: {exc}")
        raise


@celery_app.task
def extract_entities(threat_id: int):
    """Extract entities (IOCs, TTPs) from threat description"""
    try:
        extractor = EntityExtractor()
        result = extractor.extract_from_threat(threat_id)
        logger.info(f"Entities extracted for threat {threat_id}")
        return result
    except Exception as exc:
        logger.error(f"Entity extraction failed for {threat_id}: {exc}")
        raise


@celery_app.task
def process_threat_text(threat_id: int):
    """Complete NLP processing pipeline for a threat"""
    try:
        # Generate summary
        summary_result = generate_threat_summary.delay(threat_id)
        
        # Extract entities
        entities_result = extract_entities.delay(threat_id)
        
        return {
            "summary_task": summary_result.id,
            "entities_task": entities_result.id
        }
    except Exception as exc:
        logger.error(f"NLP processing failed for {threat_id}: {exc}")
        raise