"""
Fast Vulnerability Scanner Plugin

Performs essential vulnerability checks quickly and efficiently.
"""

import asyncio
import aiohttp
from typing import Dict, Any
from .base import VulnPlugin


class FastVulnScannerPlugin(VulnPlugin):
    """
    Fast vulnerability scanner focusing on critical security issues.
    """

    def __init__(self):
        super().__init__(name="FastVulnScanner",
                         description="Fast Essential Vulnerability Detection")
        self.vulnerabilities = []

    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform fast vulnerability scanning with essential checks.
        """
        self.vulnerabilities = []

        results = {
            'target': target,
            'vulnerabilities': [],
            'security_headers': {},
            'open_ports': [],
            'cms_info': {}
        }

        # Run essential checks concurrently but with timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(
                    self.check_security_headers(target, results),
                    self.check_common_issues(target, results),
                    self.check_critical_ports(target, results),
                    return_exceptions=True
                ),
                timeout=15  # 15 second timeout for all checks
            )
        except asyncio.TimeoutError:
            # Add timeout as a vulnerability indicator
            vuln = {
                'type': 'Network',
                'severity': 'LOW',
                'title': 'Slow Response Time',
                'description': 'Target response time exceeded 15 seconds',
                'recommendation': 'Check server performance and network connectivity'}
            self.vulnerabilities.append(vuln)

        # Compile final vulnerability list
        results['vulnerabilities'] = self.vulnerabilities
        results['vulnerability_count'] = len(self.vulnerabilities)

        return results

    async def check_security_headers(self, target: str, results: Dict) -> None:
        """Check for critical missing security headers."""
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for protocol in ['http', 'https']:
                    try:
                        url = f'{protocol}://{target}'
                        async with session.get(url, allow_redirects=False) as response:
                            headers = response.headers
                            self._analyze_headers(
                                headers, results, protocol.upper())
                            break  # If one protocol works, don't try the other
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                        continue
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass

    def _analyze_headers(
            self,
            headers: Dict,
            results: Dict,
            protocol: str) -> None:
        """Analyze critical security headers."""
        critical_headers = {
            'X-Frame-Options': 'HIGH',
            'Content-Security-Policy': 'CRITICAL',
            'Strict-Transport-Security': 'HIGH',
            'X-Content-Type-Options': 'MEDIUM'
        }

        for header, severity in critical_headers.items():
            if header not in headers:
                vuln = {
                    'type': 'Security Headers',
                    'severity': severity,
                    'title': f'Missing {header} Header',
                    'description': f'Critical security header missing: {header}',
                    'protocol': protocol,
                    'recommendation': f'Add {header} header to prevent security attacks'}
                self.vulnerabilities.append(vuln)
                results['security_headers'][header] = 'MISSING'
            else:
                results['security_headers'][header] = 'PRESENT'

        # Check for information disclosure
        if 'Server' in headers:
            server_info = headers['Server']
            if any(tech in server_info.lower()
                   for tech in ['apache', 'nginx', 'iis']):
                vuln = {
                    'type': 'Information Disclosure',
                    'severity': 'LOW',
                    'title': 'Server Information Disclosed',
                    'description': f'Server header reveals: {server_info}',
                    'recommendation': 'Hide server information in HTTP headers'
                }
                self.vulnerabilities.append(vuln)

    async def check_common_issues(self, target: str, results: Dict) -> None:
        """Check for common web application vulnerabilities."""
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Check for robots.txt (information disclosure)
                try:
                    async with session.get(f'http://{target}/robots.txt') as response:
                        if response.status == 200:
                            text = await response.text()
                            if 'Disallow:' in text and (
                                    'admin' in text.lower() or 'private' in text.lower()):
                                vuln = {
                                    'type': 'Information Disclosure',
                                    'severity': 'MEDIUM',
                                    'title': 'Sensitive Paths in robots.txt',
                                    'description': 'robots.txt reveals sensitive directory paths',
                                    'path': '/robots.txt',
                                    'recommendation': 'Remove sensitive paths from robots.txt'}
                                self.vulnerabilities.append(vuln)
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    pass

                # Check for common admin interfaces
                admin_paths = [
                    '/admin',
                    '/wp-admin',
                    '/administrator',
                    '/phpmyadmin']
                for path in admin_paths:
                    try:
                        async with session.get(f'http://{target}{path}', allow_redirects=False) as response:
                            if response.status in [200, 301, 302, 401, 403]:
                                vuln = {
                                    'type': 'Access Control',
                                    'severity': 'HIGH' if response.status == 200 else 'MEDIUM',
                                    'title': 'Admin Interface Accessible',
                                    'description': f'Admin interface found at {path} (Status: {
                                        response.status})',
                                    'path': path,
                                    'recommendation': 'Restrict access to admin interfaces'}
                                self.vulnerabilities.append(vuln)
                                break  # Only report first found admin interface
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                        continue

                # Quick CMS detection
                try:
                    async with session.get(f'http://{target}') as response:
                        content = await response.text()
                        headers = response.headers

                        # WordPress detection
                        if 'wp-content' in content or 'wp-includes' in content:
                            results['cms_info']['type'] = 'WordPress'

                            # Check for version disclosure
                            if 'wp-includes/version.php' in content or 'generator' in content.lower():
                                vuln = {
                                    'type': 'CMS',
                                    'severity': 'LOW',
                                    'title': 'WordPress Version Disclosure',
                                    'description': 'WordPress version information is exposed',
                                    'recommendation': 'Hide WordPress version information'}
                                self.vulnerabilities.append(vuln)

                        # Check for PHP version disclosure
                        if 'X-Powered-By' in headers and 'PHP' in headers['X-Powered-By']:
                            vuln = {
                                'type': 'Information Disclosure',
                                'severity': 'LOW',
                                'title': 'PHP Version Disclosure',
                                'description': f'PHP version exposed: {
                                    headers["X-Powered-By"]}',
                                'recommendation': 'Hide PHP version in HTTP headers'}
                            self.vulnerabilities.append(vuln)
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    pass

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass

    async def check_critical_ports(self, target: str, results: Dict) -> None:
        """Check for critical open ports that pose security risks."""
        critical_ports = {
            21: ('FTP', 'HIGH'),
            22: ('SSH', 'MEDIUM'),
            23: ('Telnet', 'CRITICAL'),
            25: ('SMTP', 'MEDIUM'),
            80: ('HTTP', 'LOW'),
            443: ('HTTPS', 'LOW'),
            3389: ('RDP', 'HIGH'),
            5432: ('PostgreSQL', 'HIGH'),
            3306: ('MySQL', 'HIGH'),
            6379: ('Redis', 'CRITICAL'),
            27017: ('MongoDB', 'CRITICAL')
        }

        # Quick port scan with limited timeout
        tasks = []
        for port, (service, severity) in critical_ports.items():
            tasks.append(
                self._quick_port_check(
                    target,
                    port,
                    service,
                    severity))

        try:
            port_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=8
            )

            for result in port_results:
                if result and not isinstance(result, Exception):
                    port, service, severity, is_open = result
                    if is_open:
                        results['open_ports'].append(
                            {'port': port, 'service': service})

                        if severity in ['HIGH', 'CRITICAL']:
                            vuln = {
                                'type': 'Open Port',
                                'severity': severity,
                                'title': f'{service} Service Exposed',
                                'description': f'{service} running on port {port} may be vulnerable',
                                'port': port,
                                'service': service,
                                'recommendation': f'Secure or disable {service} service if not needed'}
                            self.vulnerabilities.append(vuln)

        except asyncio.TimeoutError:
            pass  # Port scan timeout, continue with other checks

    async def _quick_port_check(
            self,
            target: str,
            port: int,
            service: str,
            severity: str) -> tuple:
        """Quick port connectivity check."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=2
            )
            writer.close()
            await writer.wait_closed()
            return (port, service, severity, True)
        except (OSError, asyncio.TimeoutError):
            return (port, service, severity, False)

    def get_plugin_info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.plugin_type,
            "version": "1.0.0",
            "checks": "Security Headers, Admin Interfaces, CMS Detection, Critical Ports"}
