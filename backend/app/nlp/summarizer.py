"""
Threat summarization using NLP
"""

import logging
from typing import Dict, Any, Optional
from transformers import pipeline, AutoTokenizer, AutoModelForSeq2SeqLM

logger = logging.getLogger(__name__)


class ThreatSummarizer:
    """NLP-based threat summarization system"""
    
    def __init__(self):
        self.model_name = "facebook/bart-large-cnn"
        self.summarizer = None
        self.max_length = 150
        self.min_length = 50
    
    def _initialize_model(self):
        """Initialize the summarization model"""
        try:
            if self.summarizer is None:
                logger.info("Loading BART summarization model...")
                self.summarizer = pipeline(
                    "summarization",
                    model=self.model_name,
                    tokenizer=self.model_name,
                    device=-1  # Use CPU
                )
                logger.info("Summarization model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading summarization model: {e}")
            # Fallback to simple extractive summarization
            self.summarizer = None
    
    def summarize_threat(self, threat_id: int) -> Dict[str, Any]:
        """Generate summary for a threat"""
        try:
            # TODO: Load threat data from database
            # For now, use dummy data
            threat_text = self._get_threat_text(threat_id)
            
            if not threat_text or len(threat_text.strip()) < 100:
                return {
                    "threat_id": threat_id,
                    "summary": "Insufficient text for summarization",
                    "method": "none",
                    "confidence": 0.0
                }
            
            # Initialize model if needed
            self._initialize_model()
            
            if self.summarizer:
                # Use BART for abstractive summarization
                summary = self._abstractive_summarization(threat_text)
                method = "abstractive"
                confidence = 0.85
            else:
                # Fallback to extractive summarization
                summary = self._extractive_summarization(threat_text)
                method = "extractive"
                confidence = 0.70
            
            # TODO: Store summary in database
            
            result = {
                "threat_id": threat_id,
                "summary": summary,
                "method": method,
                "confidence": confidence,
                "original_length": len(threat_text),
                "summary_length": len(summary)
            }
            
            logger.info(f"Summary generated for threat {threat_id} using {method} method")
            return result
            
        except Exception as e:
            logger.error(f"Error summarizing threat {threat_id}: {e}")
            raise
    
    def _abstractive_summarization(self, text: str) -> str:
        """Generate abstractive summary using BART"""
        try:
            # Split text if too long
            max_input_length = 1024
            if len(text) > max_input_length:
                text = text[:max_input_length]
            
            result = self.summarizer(
                text,
                max_length=self.max_length,
                min_length=self.min_length,
                do_sample=False
            )
            
            return result[0]['summary_text']
            
        except Exception as e:
            logger.error(f"Error in abstractive summarization: {e}")
            # Fallback to extractive
            return self._extractive_summarization(text)
    
    def _extractive_summarization(self, text: str) -> str:
        """Generate extractive summary by selecting key sentences"""
        try:
            sentences = text.split('. ')
            
            # Simple scoring based on keyword frequency
            keywords = [
                'threat', 'vulnerability', 'attack', 'malware', 'exploit',
                'security', 'risk', 'compromise', 'breach', 'suspicious',
                'malicious', 'dangerous', 'critical', 'high', 'severe'
            ]
            
            scored_sentences = []
            for i, sentence in enumerate(sentences):
                score = 0
                words = sentence.lower().split()
                
                # Score based on keyword presence
                for keyword in keywords:
                    score += words.count(keyword)
                
                # Boost score for sentences with numbers (often important)
                if any(char.isdigit() for char in sentence):
                    score += 1
                
                # Penalize very short or very long sentences
                if 50 <= len(sentence) <= 200:
                    score += 1
                
                scored_sentences.append((score, i, sentence))
            
            # Sort by score and select top sentences
            scored_sentences.sort(key=lambda x: x[0], reverse=True)
            
            # Select top 2-3 sentences
            selected = scored_sentences[:3]
            selected.sort(key=lambda x: x[1])  # Sort by original order
            
            summary = '. '.join([s[2] for s in selected])
            
            # Ensure summary isn't too long
            if len(summary) > self.max_length * 2:
                summary = summary[:self.max_length * 2] + "..."
            
            return summary
            
        except Exception as e:
            logger.error(f"Error in extractive summarization: {e}")
            # Return first few sentences as fallback
            sentences = text.split('. ')[:2]
            return '. '.join(sentences)
    
    def _get_threat_text(self, threat_id: int) -> str:
        """Get threat text from database"""
        # TODO: Load from database
        # For now, return dummy text
        return """
        A critical vulnerability has been discovered in the widely-used Apache Log4j logging library, 
        tracked as CVE-2021-44228. This vulnerability allows remote code execution through log injection 
        and has been exploited in the wild. The vulnerability affects Log4j versions 2.0-beta9 through 2.14.1. 
        Attackers can exploit this vulnerability by sending specially crafted requests that trigger 
        the vulnerable code path. The impact is severe as it allows complete system compromise. 
        Organizations should immediately update to Log4j version 2.15.0 or later, or implement 
        appropriate mitigations. This vulnerability has been assigned a CVSS score of 10.0, 
        indicating critical severity. Widespread exploitation attempts have been observed across 
        the internet targeting various applications and services that use the vulnerable library.
        """