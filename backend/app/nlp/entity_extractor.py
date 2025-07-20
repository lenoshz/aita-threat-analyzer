"""
Entity extraction for cybersecurity threats
"""

import logging
import re
from typing import Dict, Any, List
import spacy
from spacy import displacy

logger = logging.getLogger(__name__)


class EntityExtractor:
    """NLP-based entity extraction for cybersecurity data"""
    
    def __init__(self):
        self.nlp = None
        self.ioc_patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'cve': r'CVE-\d{4}-\d{4,7}',
            'cpe': r'cpe:2\.3:[aho\*\-]',
        }
        
        self.attack_patterns = {
            'malware_families': [
                'wannacry', 'petya', 'notpetya', 'ryuk', 'maze', 'revil', 'conti',
                'emotet', 'trickbot', 'qakbot', 'dridex', 'zeus', 'carbanak'
            ],
            'attack_techniques': [
                'sql injection', 'xss', 'csrf', 'lfi', 'rfi', 'xxe', 'ssrf',
                'privilege escalation', 'lateral movement', 'data exfiltration',
                'command injection', 'buffer overflow', 'heap overflow'
            ],
            'attack_vectors': [
                'phishing', 'spear phishing', 'watering hole', 'drive by download',
                'supply chain', 'insider threat', 'social engineering'
            ]
        }
    
    def _initialize_nlp(self):
        """Initialize spaCy NLP model"""
        try:
            if self.nlp is None:
                # Try to load the model, fallback if not available
                try:
                    self.nlp = spacy.load("en_core_web_sm")
                except OSError:
                    logger.warning("spaCy model not found, using blank model")
                    self.nlp = spacy.blank("en")
                logger.info("NLP model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading NLP model: {e}")
            self.nlp = None
    
    def extract_from_threat(self, threat_id: int) -> Dict[str, Any]:
        """Extract entities from threat description"""
        try:
            # TODO: Load threat data from database
            threat_text = self._get_threat_text(threat_id)
            
            if not threat_text:
                return {
                    "threat_id": threat_id,
                    "entities": {},
                    "iocs": {},
                    "attack_patterns": {},
                    "confidence": 0.0
                }
            
            # Extract IOCs using regex patterns
            iocs = self._extract_iocs(threat_text)
            
            # Extract named entities using spaCy
            entities = self._extract_named_entities(threat_text)
            
            # Extract attack patterns
            attack_patterns = self._extract_attack_patterns(threat_text)
            
            # Calculate overall confidence
            confidence = self._calculate_confidence(iocs, entities, attack_patterns)
            
            # TODO: Store extracted entities in database
            
            result = {
                "threat_id": threat_id,
                "entities": entities,
                "iocs": iocs,
                "attack_patterns": attack_patterns,
                "confidence": confidence,
                "total_entities": sum(len(v) if isinstance(v, list) else 1 for v in {**entities, **iocs, **attack_patterns}.values())
            }
            
            logger.info(f"Entities extracted for threat {threat_id}: {result['total_entities']} entities found")
            return result
            
        except Exception as e:
            logger.error(f"Error extracting entities for threat {threat_id}: {e}")
            raise
    
    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise using regex patterns"""
        iocs = {}
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Remove duplicates and filter out common false positives
                unique_matches = list(set(matches))
                filtered_matches = self._filter_false_positives(ioc_type, unique_matches)
                if filtered_matches:
                    iocs[ioc_type] = filtered_matches
        
        return iocs
    
    def _extract_named_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract named entities using spaCy"""
        entities = {}
        
        self._initialize_nlp()
        
        if self.nlp is None:
            return entities
        
        try:
            doc = self.nlp(text)
            
            entity_types = ['PERSON', 'ORG', 'GPE', 'PRODUCT', 'EVENT']
            
            for ent_type in entity_types:
                ents = [ent.text for ent in doc.ents if ent.label_ == ent_type]
                if ents:
                    entities[ent_type.lower()] = list(set(ents))
            
        except Exception as e:
            logger.error(f"Error in named entity extraction: {e}")
        
        return entities
    
    def _extract_attack_patterns(self, text: str) -> Dict[str, List[str]]:
        """Extract cybersecurity attack patterns"""
        patterns = {}
        text_lower = text.lower()
        
        for pattern_type, pattern_list in self.attack_patterns.items():
            found_patterns = []
            for pattern in pattern_list:
                if pattern.lower() in text_lower:
                    found_patterns.append(pattern)
            
            if found_patterns:
                patterns[pattern_type] = found_patterns
        
        return patterns
    
    def _filter_false_positives(self, ioc_type: str, matches: List[str]) -> List[str]:
        """Filter out common false positives"""
        filtered = []
        
        for match in matches:
            if ioc_type == 'ip':
                # Filter out private/reserved IPs for demo
                if not (match.startswith('192.168.') or 
                       match.startswith('10.') or 
                       match.startswith('127.') or
                       match.startswith('172.')):
                    filtered.append(match)
            elif ioc_type == 'domain':
                # Filter out common false positive domains
                if not any(fp in match.lower() for fp in ['example.com', 'test.com', 'localhost']):
                    filtered.append(match)
            else:
                filtered.append(match)
        
        return filtered
    
    def _calculate_confidence(self, iocs: Dict, entities: Dict, patterns: Dict) -> float:
        """Calculate confidence score based on extracted entities"""
        total_entities = sum(len(v) for v in {**iocs, **entities, **patterns}.values())
        
        if total_entities == 0:
            return 0.0
        
        # Weight different types of entities
        ioc_weight = 0.4
        entity_weight = 0.3
        pattern_weight = 0.3
        
        ioc_score = min(1.0, sum(len(v) for v in iocs.values()) / 5) * ioc_weight
        entity_score = min(1.0, sum(len(v) for v in entities.values()) / 5) * entity_weight
        pattern_score = min(1.0, sum(len(v) for v in patterns.values()) / 3) * pattern_weight
        
        return ioc_score + entity_score + pattern_score
    
    def _get_threat_text(self, threat_id: int) -> str:
        """Get threat text from database"""
        # TODO: Load from database
        # For now, return dummy text
        return """
        A new malware campaign has been discovered targeting financial institutions.
        The attack uses the domain malicious-bank.com to host phishing pages that 
        steal credentials. The malware communicates with C2 server at IP 203.0.113.42
        and downloads additional payloads from https://evil-site.net/payload.exe.
        The campaign uses CVE-2021-44228 for initial exploitation and employs
        SQL injection techniques to extract sensitive data. The malware family
        appears to be related to Emotet and uses spear phishing as the initial
        attack vector. Hash of the main payload: a1b2c3d4e5f6789012345678901234567890123456789012345678901234.
        """