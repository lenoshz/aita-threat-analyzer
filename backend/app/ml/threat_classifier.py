"""
Threat classification using machine learning
"""

import logging
from typing import Dict, Any, Optional
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """ML-based threat classification system"""
    
    def __init__(self):
        self.model_path = "models/threat_classifier.joblib"
        self.model = None
        self.categories = [
            "malware",
            "vulnerability",
            "phishing",
            "botnet",
            "ransomware",
            "apt",
            "ddos",
            "other"
        ]
    
    def train(self) -> Dict[str, Any]:
        """Train the threat classification model"""
        try:
            # TODO: Load training data from database
            # For now, create a dummy model
            
            # Create pipeline with TF-IDF and Random Forest
            self.model = Pipeline([
                ('tfidf', TfidfVectorizer(max_features=10000, stop_words='english')),
                ('classifier', RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                    class_weight='balanced'
                ))
            ])
            
            # Generate dummy training data
            X_train, y_train = self._generate_dummy_data()
            
            # Train the model
            self.model.fit(X_train, y_train)
            
            # Save the model
            joblib.dump(self.model, self.model_path)
            
            # Calculate metrics (on training data for demo)
            y_pred = self.model.predict(X_train)
            accuracy = accuracy_score(y_train, y_pred)
            
            logger.info(f"Threat classifier trained with accuracy: {accuracy:.3f}")
            
            return {
                "status": "success",
                "accuracy": accuracy,
                "categories": self.categories,
                "model_path": self.model_path
            }
            
        except Exception as e:
            logger.error(f"Error training threat classifier: {e}")
            raise
    
    def classify_threat(self, threat_id: int) -> Dict[str, Any]:
        """Classify a specific threat"""
        try:
            # Load model if not already loaded
            if self.model is None:
                self.model = joblib.load(self.model_path)
            
            # TODO: Load threat data from database
            # For now, use dummy data
            threat_text = "This is a sample threat description"
            
            # Make prediction
            prediction = self.model.predict([threat_text])[0]
            probabilities = self.model.predict_proba([threat_text])[0]
            
            # Get confidence score (max probability)
            confidence = float(np.max(probabilities))
            
            # TODO: Update threat record in database
            
            result = {
                "threat_id": threat_id,
                "predicted_category": prediction,
                "confidence_score": confidence,
                "probabilities": {
                    cat: float(prob) for cat, prob in zip(self.categories, probabilities)
                }
            }
            
            logger.info(f"Threat {threat_id} classified as: {prediction} (confidence: {confidence:.3f})")
            return result
            
        except Exception as e:
            logger.error(f"Error classifying threat {threat_id}: {e}")
            raise
    
    def _generate_dummy_data(self):
        """Generate dummy training data for demonstration"""
        # This would be replaced with actual threat data from the database
        dummy_texts = [
            "Malicious executable detected with suspicious behavior",
            "SQL injection vulnerability found in web application",
            "Phishing email with suspicious links detected",
            "Botnet command and control server identified",
            "Ransomware encryption detected on endpoints",
            "Advanced persistent threat campaign observed",
            "Distributed denial of service attack in progress",
            "Unknown threat with suspicious network activity"
        ] * 100  # Repeat to have more training data
        
        dummy_labels = self.categories * 100
        
        return dummy_texts, dummy_labels
    
    def load_model(self) -> bool:
        """Load trained model from disk"""
        try:
            self.model = joblib.load(self.model_path)
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False