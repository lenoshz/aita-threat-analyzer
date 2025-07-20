"""
Celery configuration for background tasks
"""

from celery import Celery
from app.core.config import settings

# Create Celery app
celery_app = Celery(
    "aita",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.threat_ingestion",
        "app.tasks.ml_processing",
        "app.tasks.nlp_processing",
        "app.tasks.correlation"
    ]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.tasks.threat_ingestion.*": {"queue": "ingestion"},
        "app.tasks.ml_processing.*": {"queue": "ml"},
        "app.tasks.nlp_processing.*": {"queue": "nlp"},
        "app.tasks.correlation.*": {"queue": "correlation"},
    },
    task_default_queue="default",
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=100,
)

# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "sync-cve-feed": {
        "task": "app.tasks.threat_ingestion.sync_cve_feed",
        "schedule": 3600.0,  # Every hour
    },
    "sync-ip-blacklists": {
        "task": "app.tasks.threat_ingestion.sync_ip_blacklists", 
        "schedule": 1800.0,  # Every 30 minutes
    },
    "train-ml-models": {
        "task": "app.tasks.ml_processing.train_models",
        "schedule": 86400.0,  # Daily
    },
    "process-log-correlation": {
        "task": "app.tasks.correlation.process_correlations",
        "schedule": 300.0,  # Every 5 minutes
    },
}