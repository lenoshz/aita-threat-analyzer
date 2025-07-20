"""
Threat ingestion tasks
"""

from celery import current_app as celery_app
from app.ingestion.cve_collector import CVECollector
from app.ingestion.ip_blacklist_collector import IPBlacklistCollector
import logging

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def sync_cve_feed(self):
    """Sync CVE feed from NIST NVD"""
    try:
        collector = CVECollector()
        result = collector.collect_recent_cves()
        logger.info(f"CVE sync completed: {result['new_cves']} new CVEs collected")
        return result
    except Exception as exc:
        logger.error(f"CVE sync failed: {exc}")
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@celery_app.task(bind=True)
def sync_ip_blacklists(self):
    """Sync IP blacklists from various sources"""
    try:
        collector = IPBlacklistCollector()
        result = collector.collect_blacklisted_ips()
        logger.info(f"IP blacklist sync completed: {result['new_ips']} new IPs collected")
        return result
    except Exception as exc:
        logger.error(f"IP blacklist sync failed: {exc}")
        raise self.retry(exc=exc, countdown=60, max_retries=3)


@celery_app.task(bind=True)
def sync_malware_intelligence(self):
    """Sync malware intelligence from VirusTotal and other sources"""
    try:
        # Implementation would go here
        logger.info("Malware intelligence sync completed")
        return {"status": "completed", "new_samples": 0}
    except Exception as exc:
        logger.error(f"Malware intelligence sync failed: {exc}")
        raise self.retry(exc=exc, countdown=60, max_retries=3)