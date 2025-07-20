"""
CVE collector for NIST NVD API integration
"""

import httpx
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta
from app.core.config import settings

logger = logging.getLogger(__name__)


class CVECollector:
    """Collector for CVE data from NIST NVD API"""
    
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json"
        self.api_key = settings.NIST_NVD_API_KEY
        self.headers = {
            "User-Agent": "AITA-ThreatAnalyzer/1.0",
        }
        if self.api_key:
            self.headers["apiKey"] = self.api_key
    
    async def collect_recent_cves(self, days: int = 1) -> Dict[str, Any]:
        """Collect CVEs from the last N days"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": 2000,
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/cves/2.0",
                    headers=self.headers,
                    params=params,
                    timeout=30.0
                )
                response.raise_for_status()
                
                data = response.json()
                cves = data.get("vulnerabilities", [])
                
                # Process and store CVEs
                new_cves = await self._process_cves(cves)
                
                return {
                    "status": "success",
                    "new_cves": len(new_cves),
                    "total_retrieved": len(cves)
                }
                
        except Exception as e:
            logger.error(f"Error collecting CVEs: {e}")
            raise
    
    async def _process_cves(self, cves: List[Dict]) -> List[str]:
        """Process and store CVE data"""
        new_cves = []
        
        for vuln in cves:
            try:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id")
                
                if not cve_id:
                    continue
                
                # Extract CVE data
                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Extract CVSS scores
                metrics = cve.get("metrics", {})
                cvss_score = None
                cvss_vector = None
                
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                
                # Determine severity
                severity = self._get_severity_from_cvss(cvss_score)
                
                # TODO: Store in database
                # For now, just log
                logger.info(f"Processed CVE: {cve_id}")
                new_cves.append(cve_id)
                
            except Exception as e:
                logger.error(f"Error processing CVE: {e}")
                continue
        
        return new_cves
    
    def _get_severity_from_cvss(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score is None:
            return "unknown"
        elif cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"