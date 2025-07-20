"""
Risk scoring using machine learning
"""

import logging
from typing import Dict, Any, Optional
import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import mean_squared_error, r2_score

logger = logging.getLogger(__name__)


class RiskScorer:
    """ML-based risk scoring system"""
    
    def __init__(self):
        self.model_path = "models/risk_scorer.joblib"
        self.model = None
        self.feature_names = [
            "cvss_score",
            "source_reliability",
            "threat_age_days",
            "ioc_count",
            "external_references",
            "exploit_availability",
            "target_prevalence"
        ]
    
    def train(self) -> Dict[str, Any]:
        """Train the risk scoring model"""
        try:
            # Create pipeline with scaling and gradient boosting
            self.model = Pipeline([
                ('scaler', StandardScaler()),
                ('regressor', GradientBoostingRegressor(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=5,
                    random_state=42
                ))
            ])
            
            # Generate dummy training data
            X_train, y_train = self._generate_dummy_data()
            
            # Train the model
            self.model.fit(X_train, y_train)
            
            # Save the model
            joblib.dump(self.model, self.model_path)
            
            # Calculate metrics
            y_pred = self.model.predict(X_train)
            mse = mean_squared_error(y_train, y_pred)
            r2 = r2_score(y_train, y_pred)
            
            logger.info(f"Risk scorer trained with R² score: {r2:.3f}")
            
            return {
                "status": "success",
                "r2_score": r2,
                "mse": mse,
                "features": self.feature_names,
                "model_path": self.model_path
            }
            
        except Exception as e:
            logger.error(f"Error training risk scorer: {e}")
            raise
    
    def score_threat(self, threat_id: int) -> Dict[str, Any]:
        """Calculate risk score for a specific threat"""
        try:
            # Load model if not already loaded
            if self.model is None:
                self.model = joblib.load(self.model_path)
            
            # TODO: Extract features from threat data in database
            # For now, use dummy features
            features = self._extract_features(threat_id)
            
            # Make prediction
            risk_score = self.model.predict([features])[0]
            
            # Ensure score is between 0 and 10
            risk_score = max(0.0, min(10.0, risk_score))
            
            # Calculate risk level
            risk_level = self._get_risk_level(risk_score)
            
            # TODO: Update threat record in database
            
            result = {
                "threat_id": threat_id,
                "risk_score": float(risk_score),
                "risk_level": risk_level,
                "features_used": dict(zip(self.feature_names, features))
            }
            
            logger.info(f"Risk score calculated for threat {threat_id}: {risk_score:.2f} ({risk_level})")
            return result
            
        except Exception as e:
            logger.error(f"Error scoring threat {threat_id}: {e}")
            raise
    
    def _extract_features(self, threat_id: int) -> list:
        """Extract features for risk scoring"""
        # TODO: Extract actual features from database
        # For now, return dummy features
        return [
            7.5,  # cvss_score
            0.8,  # source_reliability
            5.0,  # threat_age_days
            12.0, # ioc_count
            3.0,  # external_references
            0.6,  # exploit_availability
            0.7   # target_prevalence
        ]
    
    def _generate_dummy_data(self):
        """Generate dummy training data"""
        np.random.seed(42)
        n_samples = 1000
        
        # Generate features
        X = np.random.rand(n_samples, len(self.feature_names)) * 10
        
        # Generate target (risk scores 0-10)
        # Make it somewhat correlated with features
        y = (
            X[:, 0] * 0.4 +  # CVSS score weight
            X[:, 1] * 0.2 +  # Source reliability weight
            (10 - X[:, 2]) * 0.1 +  # Threat age (newer = higher risk)
            np.log1p(X[:, 3]) * 0.2 +  # IOC count weight
            X[:, 4] * 0.1 +  # External references weight
            np.random.normal(0, 1, n_samples)  # Random noise
        )
        
        # Normalize to 0-10 range
        y = np.clip(y, 0, 10)
        
        return X, y
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert numerical risk score to risk level"""
        if risk_score >= 8.0:
            return "critical"
        elif risk_score >= 6.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        elif risk_score >= 2.0:
            return "low"
        else:
            return "minimal"
    
    def load_model(self) -> bool:
        """Load trained model from disk"""
        try:
            self.model = joblib.load(self.model_path)
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False