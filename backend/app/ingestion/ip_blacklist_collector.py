"""
IP blacklist collector for threat intelligence
"""

import httpx
import logging
from typing import Dict, List, Any, Set
from app.core.config import settings

logger = logging.getLogger(__name__)


class IPBlacklistCollector:
    """Collector for IP blacklists from various sources"""
    
    def __init__(self):
        self.sources = {
            "abuse_ch": {
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "format": "text"
            },
            "emergingthreats": {
                "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                "format": "text"
            },
            "spamhaus": {
                "url": "https://www.spamhaus.org/drop/drop.txt",
                "format": "cidr"
            }
        }
    
    async def collect_blacklisted_ips(self) -> Dict[str, Any]:
        """Collect IP blacklists from all sources"""
        all_ips = set()
        source_stats = {}
        
        for source_name, source_config in self.sources.items():
            try:
                ips = await self._collect_from_source(source_name, source_config)
                all_ips.update(ips)
                source_stats[source_name] = len(ips)
                logger.info(f"Collected {len(ips)} IPs from {source_name}")
            except Exception as e:
                logger.error(f"Failed to collect from {source_name}: {e}")
                source_stats[source_name] = 0
        
        # TODO: Store in database and update existing records
        new_ips = await self._store_ips(all_ips)
        
        return {
            "status": "success",
            "new_ips": len(new_ips),
            "total_ips": len(all_ips),
            "sources": source_stats
        }
    
    async def _collect_from_source(self, source_name: str, config: Dict) -> Set[str]:
        """Collect IPs from a specific source"""
        ips = set()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    config["url"],
                    timeout=30.0,
                    headers={"User-Agent": "AITA-ThreatAnalyzer/1.0"}
                )
                response.raise_for_status()
                
                content = response.text
                
                if config["format"] == "text":
                    ips = self._parse_text_format(content)
                elif config["format"] == "cidr":
                    ips = self._parse_cidr_format(content)
                    
        except Exception as e:
            logger.error(f"Error collecting from {source_name}: {e}")
            raise
        
        return ips
    
    def _parse_text_format(self, content: str) -> Set[str]:
        """Parse simple text format (one IP per line)"""
        ips = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and self._is_valid_ip(line):
                ips.add(line)
        
        return ips
    
    def _parse_cidr_format(self, content: str) -> Set[str]:
        """Parse CIDR format"""
        ips = set()
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract IP/CIDR from line (may have comments)
                parts = line.split(';')[0].strip()
                if self._is_valid_cidr(parts):
                    ips.add(parts)
        
        return ips
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP validation"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def _is_valid_cidr(self, cidr: str) -> bool:
        """Basic CIDR validation"""
        try:
            if '/' in cidr:
                ip, mask = cidr.split('/')
                return self._is_valid_ip(ip) and 0 <= int(mask) <= 32
            else:
                return self._is_valid_ip(cidr)
        except:
            return False
    
    async def _store_ips(self, ips: Set[str]) -> List[str]:
        """Store IPs in database"""
        # TODO: Implement database storage
        # For now, just return the IPs as "new"
        return list(ips)