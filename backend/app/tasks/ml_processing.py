"""
ML processing tasks
"""

from celery import current_app as celery_app
from app.ml.threat_classifier import ThreatClassifier
from app.ml.risk_scorer import RiskScorer
import logging

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def train_models(self):
    """Train and update ML models"""
    try:
        # Train threat classification model
        classifier = ThreatClassifier()
        classifier_result = classifier.train()
        
        # Train risk scoring model  
        risk_scorer = RiskScorer()
        risk_result = risk_scorer.train()
        
        logger.info("ML model training completed successfully")
        return {
            "classifier": classifier_result,
            "risk_scorer": risk_result
        }
    except Exception as exc:
        logger.error(f"ML model training failed: {exc}")
        raise self.retry(exc=exc, countdown=300, max_retries=2)


@celery_app.task
def classify_threat(threat_id: int):
    """Classify a specific threat using ML models"""
    try:
        classifier = ThreatClassifier()
        result = classifier.classify_threat(threat_id)
        logger.info(f"Threat {threat_id} classified successfully")
        return result
    except Exception as exc:
        logger.error(f"Threat classification failed for {threat_id}: {exc}")
        raise


@celery_app.task
def calculate_risk_score(threat_id: int):
    """Calculate risk score for a specific threat"""
    try:
        risk_scorer = RiskScorer()
        result = risk_scorer.score_threat(threat_id)
        logger.info(f"Risk score calculated for threat {threat_id}")
        return result
    except Exception as exc:
        logger.error(f"Risk scoring failed for {threat_id}: {exc}")
        raise