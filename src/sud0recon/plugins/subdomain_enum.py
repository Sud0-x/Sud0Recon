"""
Subdomain Enumeration Plugin

This module defines a plugin for subdomain enumeration.
"""

from typing import Dict, Any
import asyncio
import aiohttp
from .base import ReconPlugin


class SubdomainEnumPlugin(ReconPlugin):
    """
    Plugin for subdomain enumeration using a DNS brute force approach.
    """

    def __init__(self):
        super().__init__(name="SubdomainEnum", description="Subdomain Enumeration Plugin")
        self.subdomains = ["www", "api", "mail", "dev", "test"]

    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        results = {"found_subdomains": []}
        base_domain = target

        async with aiohttp.ClientSession() as session:
            tasks = []
            for subdomain in self.subdomains:
                full_domain = f"{subdomain}.{base_domain}"
                tasks.append(self.check_subdomain(full_domain, session))

            resolved_subdomains = await asyncio.gather(*tasks)
            results["found_subdomains"] = [
                sub for sub in resolved_subdomains if sub]
        return results

    async def check_subdomain(
            self,
            domain: str,
            session: aiohttp.ClientSession) -> str:
        """Check if a subdomain resolves."""
        try:
            async with session.get(f"http://{domain}", timeout=5) as resp:
                if resp.status == 200:
                    return domain
        except Exception:
            return ""

    def get_plugin_info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.plugin_type
        }
