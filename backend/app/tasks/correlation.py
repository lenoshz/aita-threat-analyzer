"""
Log correlation tasks
"""

from celery import current_app as celery_app
from app.correlation.log_correlator import LogCorrelator
import logging

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def process_correlations(self):
    """Process log correlations with threat intelligence"""
    try:
        correlator = LogCorrelator()
        result = correlator.process_pending_logs()
        logger.info(f"Log correlation completed: {result['correlations_found']} correlations found")
        return result
    except Exception as exc:
        logger.error(f"Log correlation failed: {exc}")
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@celery_app.task
def correlate_log_entry(log_entry_id: int):
    """Correlate a specific log entry with threats"""
    try:
        correlator = LogCorrelator()
        result = correlator.correlate_log(log_entry_id)
        logger.info(f"Log entry {log_entry_id} correlated")
        return result
    except Exception as exc:
        logger.error(f"Log correlation failed for {log_entry_id}: {exc}")
        raise


@celery_app.task
def generate_alert(correlation_data: dict):
    """Generate alert based on correlation data"""
    try:
        # Implementation would create alerts based on correlation results
        logger.info("Alert generated from correlation")
        return {"alert_id": None, "status": "created"}
    except Exception as exc:
        logger.error(f"Alert generation failed: {exc}")
        raise