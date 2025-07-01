"""
Port Scanner Plugin

This module defines a plugin for port scanning.
"""

import asyncio
from typing import Dict, Any
from .base import ReconPlugin


class PortScannerPlugin(ReconPlugin):
    """
    Plugin for port scanning using TCP connect scans.
    """

    def __init__(self):
        super().__init__(name="PortScanner", description="TCP Port Scanner Plugin")
        # Common ports to scan
        self.common_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            993,
            995,
            8080,
            8443]

    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Scan common ports on the target.

        Args:
            target: Target IP address or hostname
            **kwargs: Additional options (ports, timeout)

        Returns:
            Dict with scan results
        """
        ports_to_scan = kwargs.get('ports', self.common_ports)
        timeout = kwargs.get('timeout', 3)

        results = {
            'target': target,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': []
        }

        # Create scanning tasks
        tasks = []
        for port in ports_to_scan:
            task = asyncio.create_task(self.scan_port(target, port, timeout))
            tasks.append(task)

        # Execute all scans concurrently
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for i, result in enumerate(scan_results):
            port = ports_to_scan[i]
            if isinstance(result, Exception):
                results['filtered_ports'].append(port)
            elif result:
                results['open_ports'].append(port)
            else:
                results['closed_ports'].append(port)

        return results

    async def scan_port(self, target: str, port: int, timeout: int) -> bool:
        """
        Scan a single port on the target.

        Args:
            target: Target IP or hostname
            port: Port number to scan
            timeout: Connection timeout

        Returns:
            True if port is open, False if closed
        """
        try:
            # Create a socket connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def banner_grab(
            self,
            target: str,
            port: int,
            timeout: int = 5) -> str:
        """
        Attempt to grab a banner from an open port.

        Args:
            target: Target IP or hostname
            port: Port number
            timeout: Connection timeout

        Returns:
            Banner string if available, empty string otherwise
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )

            # Try to read a banner
            banner_data = await asyncio.wait_for(
                reader.read(1024),
                timeout=2
            )

            writer.close()
            await writer.wait_closed()

            return banner_data.decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    def get_plugin_info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.plugin_type,
            "default_ports": str(self.common_ports)
        }
