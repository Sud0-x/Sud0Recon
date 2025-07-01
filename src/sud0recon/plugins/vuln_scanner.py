"""
Real Vulnerability Scanner Plugin

This module implements actual vulnerability detection capabilities.
"""

import asyncio
import aiohttp
import ssl
import socket
from typing import Dict, Any
from .base import VulnPlugin


class VulnScannerPlugin(VulnPlugin):
    """
    Real vulnerability scanner that detects actual security issues.
    """

    def __init__(self):
        super().__init__(
            name="VulnScanner",
            description="Real Vulnerability Detection Plugin")
        self.vulnerabilities = []

    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform comprehensive vulnerability scanning.
        """
        self.vulnerabilities = []

        results = {
            'target': target,
            'vulnerabilities': [],
            'security_headers': {},
            'ssl_issues': [],
            'open_ports': [],
            'cms_detection': {},
            'directory_traversal': False,
            'sql_injection': False,
            'xss_vulnerable': False,
            'scan_time': 0
        }

        # Run all vulnerability checks
        await asyncio.gather(
            self.check_ssl_vulnerabilities(target, results),
            self.check_security_headers(target, results),
            self.check_common_vulnerabilities(target, results),
            self.check_cms_vulnerabilities(target, results),
            self.check_directory_traversal(target, results),
            self.check_sql_injection(target, results),
            self.check_xss_vulnerabilities(target, results),
            self.check_open_ports(target, results),
            return_exceptions=True
        )

        # Compile final vulnerability list
        results['vulnerabilities'] = self.vulnerabilities
        results['vulnerability_count'] = len(self.vulnerabilities)

        return results

    async def check_ssl_vulnerabilities(
            self, target: str, results: Dict) -> None:
        """Check for SSL/TLS vulnerabilities."""
        try:
            # Check SSL certificate issues
            context = ssl.create_default_context()

            # Test for weak SSL protocols
            for protocol in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1]:
                try:
                    weak_context = ssl.SSLContext(protocol)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    ssl_sock = weak_context.wrap_socket(sock)
                    await asyncio.get_event_loop().run_in_executor(
                        None, ssl_sock.connect, (target, 443)
                    )
                    ssl_sock.close()

                    vuln = {
                        'type': 'SSL/TLS',
                        'severity': 'HIGH',
                        'title': 'Weak SSL Protocol Supported',
                        'description': f'Server supports weak {
                            str(protocol)} protocol',
                        'port': 443,
                        'cve': 'CVE-2014-3566' if 'TLSv1' in str(protocol) else None,
                        'recommendation': 'Disable weak SSL/TLS protocols and use TLS 1.2+ only'}
                    self.vulnerabilities.append(vuln)
                    results['ssl_issues'].append(
                        f'Weak protocol: {protocol.name}')

                except (ConnectionRefusedError, OSError, ssl.SSLError):
                    pass  # Protocol not supported (good)

            # Check for certificate issues
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                ssl_sock = context.wrap_socket(sock, server_hostname=target)
                await asyncio.get_event_loop().run_in_executor(
                    None, ssl_sock.connect, (target, 443)
                )
                cert = ssl_sock.getpeercert()
                ssl_sock.close()

                # Check certificate expiry
                import datetime
                not_after = datetime.datetime.strptime(
                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.datetime.now()).days

                if days_until_expiry < 30:
                    vuln = {
                        'type': 'SSL Certificate',
                        'severity': 'MEDIUM' if days_until_expiry > 0 else 'HIGH',
                        'title': (
                            'SSL Certificate Expiring Soon' if days_until_expiry > 0
                            else 'SSL Certificate Expired'
                        ),
                        'description': f'SSL certificate expires in {days_until_expiry} days',
                        'port': 443,
                        'recommendation': 'Renew SSL certificate before expiration'}
                    self.vulnerabilities.append(vuln)

            except (ssl.SSLError, OSError, ConnectionRefusedError):
                # Could be self-signed or invalid certificate
                vuln = {
                    'type': 'SSL Certificate',
                    'severity': 'HIGH',
                    'title': 'Invalid SSL Certificate',
                    'description': 'SSL certificate is invalid, self-signed, or untrusted',
                    'port': 443,
                    'recommendation': 'Install a valid SSL certificate from a trusted CA'}
                self.vulnerabilities.append(vuln)
                results['ssl_issues'].append('Invalid/Self-signed certificate')

        except (OSError, ssl.SSLError, ConnectionRefusedError):
            pass  # No SSL or connection failed

    async def check_security_headers(self, target: str, results: Dict) -> None:
        """Check for missing security headers."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                try:
                    async with session.get(f'http://{target}', allow_redirects=False) as response:
                        headers = response.headers
                        self._analyze_security_headers(
                            headers, results, 'HTTP')
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

                try:
                    async with session.get(f'https://{target}', allow_redirects=False) as response:
                        headers = response.headers
                        self._analyze_security_headers(
                            headers, results, 'HTTPS')
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    def _analyze_security_headers(
            self,
            headers: Dict,
            results: Dict,
            protocol: str) -> None:
        """Analyze security headers and identify missing ones."""
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content injection protection',
            'X-Permitted-Cross-Domain-Policies': 'Cross-domain policy control',
            'Referrer-Policy': 'Referrer information control'
        }

        for header, description in security_headers.items():
            if header not in headers:
                vuln = {
                    'type': 'Security Headers',
                    'severity': 'MEDIUM' if header != 'Content-Security-Policy' else 'HIGH',
                    'title': f'Missing {header} Header',
                    'description': f'Missing security header: {header} ({description})',
                    'protocol': protocol,
                    'recommendation': f'Add {header} header to improve security'}
                self.vulnerabilities.append(vuln)
                results['security_headers'][header] = 'MISSING'
            else:
                results['security_headers'][header] = 'PRESENT'

    async def check_common_vulnerabilities(
            self, target: str, results: Dict) -> None:
        """Check for common web vulnerabilities."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                # Check for robots.txt disclosure
                try:
                    async with session.get(f'http://{target}/robots.txt') as response:
                        if response.status == 200:
                            text = await response.text()
                            if 'Disallow:' in text:
                                vuln = {
                                    'type': 'Information Disclosure',
                                    'severity': 'LOW',
                                    'title': 'Robots.txt File Exposed',
                                    'description': 'robots.txt file reveals directory structure',
                                    'path': '/robots.txt',
                                    'recommendation': 'Review robots.txt for sensitive path disclosure'}
                                self.vulnerabilities.append(vuln)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

                # Check for common admin pages
                admin_pages = [
                    '/admin',
                    '/admin.php',
                    '/administrator',
                    '/wp-admin',
                    '/phpmyadmin']
                for page in admin_pages:
                    try:
                        async with session.get(f'http://{target}{page}') as response:
                            if response.status in [200, 401, 403]:
                                vuln = {
                                    'type': 'Access Control',
                                    'severity': 'MEDIUM',
                                    'title': 'Admin Panel Accessible',
                                    'description': f'Admin panel found at {page}',
                                    'path': page,
                                    'status_code': response.status,
                                    'recommendation': (
                                        'Secure admin panels with strong authentication '
                                        'and IP restrictions'
                                    )
                                }
                                self.vulnerabilities.append(vuln)
                                break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue

                # Check for .git directory exposure
                try:
                    async with session.get(f'http://{target}/.git/config') as response:
                        if response.status == 200:
                            vuln = {
                                'type': 'Information Disclosure',
                                'severity': 'HIGH',
                                'title': 'Git Repository Exposed',
                                'description': 'Git repository files are publicly accessible',
                                'path': '/.git/',
                                'cve': 'CWE-200',
                                'recommendation': (
                                    'Remove .git directory from web root or block '
                                    'access via web server configuration'
                                )
                            }
                            self.vulnerabilities.append(vuln)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    async def check_cms_vulnerabilities(
            self, target: str, results: Dict) -> None:
        """Detect CMS and check for known vulnerabilities."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(f'http://{target}') as response:
                    content = await response.text()
                    headers = response.headers

                    # WordPress detection and checks
                    if 'wp-content' in content or 'wordpress' in content.lower():
                        results['cms_detection']['type'] = 'WordPress'

                        # Check for wp-config.php backup
                        try:
                            async with session.get(f'http://{target}/wp-config.php.bak') as wp_response:
                                if wp_response.status == 200:
                                    vuln = {
                                        'type': 'WordPress',
                                        'severity': 'CRITICAL',
                                        'title': 'WordPress Configuration Backup Exposed',
                                        'description': 'wp-config.php backup file is accessible',
                                        'path': '/wp-config.php.bak',
                                        'recommendation': 'Remove backup files from web-accessible directories'}
                                    self.vulnerabilities.append(vuln)
                        except BaseException:
                            pass

                        # Check for WordPress version disclosure
                        if 'wp-includes/version.php' in content:
                            vuln = {
                                'type': 'WordPress',
                                'severity': 'LOW',
                                'title': 'WordPress Version Disclosure',
                                'description': 'WordPress version information is exposed',
                                'recommendation': 'Hide WordPress version information'}
                            self.vulnerabilities.append(vuln)

                    # PHP detection and checks
                    if 'X-Powered-By' in headers and 'PHP' in headers['X-Powered-By']:
                        php_version = headers['X-Powered-By']
                        vuln = {
                            'type': 'Information Disclosure',
                            'severity': 'LOW',
                            'title': 'PHP Version Disclosure',
                            'description': f'PHP version exposed in headers: {php_version}',
                            'recommendation': 'Hide PHP version in X-Powered-By header'}
                        self.vulnerabilities.append(vuln)
                        results['cms_detection']['php_version'] = php_version

        except Exception:
            pass

    async def check_directory_traversal(
            self, target: str, results: Dict) -> None:
        """Test for directory traversal vulnerabilities."""
        try:
            payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ]

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for payload in payloads:
                    test_paths = [
                        f'/file?path={payload}',
                        f'/download?file={payload}',
                        f'/view/{payload}']

                    for path in test_paths:
                        try:
                            async with session.get(f'http://{target}{path}') as response:
                                content = await response.text()
                                if ('root:' in content and '/bin/' in content) or 'localhost' in content:
                                    vuln = {
                                        'type': 'Directory Traversal',
                                        'severity': 'HIGH',
                                        'title': 'Directory Traversal Vulnerability',
                                        'description': f'Directory traversal found at {path}',
                                        'path': path,
                                        'payload': payload,
                                        'cve': 'CWE-22',
                                        'recommendation': 'Implement proper input validation and sanitization'}
                                    self.vulnerabilities.append(vuln)
                                    results['directory_traversal'] = True
                                    return
                        except BaseException:
                            continue
        except Exception:
            pass

    async def check_sql_injection(self, target: str, results: Dict) -> None:
        """Test for SQL injection vulnerabilities."""
        try:
            sql_payloads = [
                "'",
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "1' UNION SELECT 1,2,3--"]

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                # Test common parameter names
                params = ['id', 'user', 'search', 'query', 'username']

                for param in params:
                    for payload in sql_payloads:
                        try:
                            url = f'http://{target}/?{param}={payload}'
                            async with session.get(url) as response:
                                content = (await response.text()).lower()

                                sql_errors = [
                                    'sql syntax',
                                    'mysql_fetch',
                                    'warning: mysql',
                                    'ora-',
                                    'microsoft ole db',
                                    'sqlite_',
                                    'postgresql',
                                    'syntax error',
                                    'quoted string not properly terminated']

                                if any(
                                        error in content for error in sql_errors):
                                    vuln = {
                                        'type': 'SQL Injection',
                                        'severity': 'CRITICAL',
                                        'title': 'SQL Injection Vulnerability',
                                        'description': f'SQL injection found in parameter: {param}',
                                        'parameter': param,
                                        'payload': payload,
                                        'cve': 'CWE-89',
                                        'recommendation': 'Use parameterized queries and input validation'}
                                    self.vulnerabilities.append(vuln)
                                    results['sql_injection'] = True
                                    return
                        except BaseException:
                            continue
        except Exception:
            pass

    async def check_xss_vulnerabilities(
            self, target: str, results: Dict) -> None:
        """Test for XSS vulnerabilities."""
        try:
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "javascript:alert('XSS')",
                '<img src=x onerror=alert("XSS")>'
            ]

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                params = ['search', 'q', 'query', 'name', 'comment']

                for param in params:
                    for payload in xss_payloads:
                        try:
                            url = f'http://{target}/?{param}={payload}'
                            async with session.get(url) as response:
                                content = await response.text()

                                if payload in content and 'text/html' in response.headers.get(
                                        'content-type', ''):
                                    vuln = {
                                        'type': 'Cross-Site Scripting (XSS)',
                                        'severity': 'HIGH',
                                        'title': 'XSS Vulnerability Detected',
                                        'description': f'XSS vulnerability found in parameter: {param}',
                                        'parameter': param,
                                        'payload': payload,
                                        'cve': 'CWE-79',
                                        'recommendation': 'Implement proper input validation and output encoding'}
                                    self.vulnerabilities.append(vuln)
                                    results['xss_vulnerable'] = True
                                    return
                        except BaseException:
                            continue
        except Exception:
            pass

    async def check_open_ports(self, target: str, results: Dict) -> None:
        """Scan for open ports and identify risky services."""
        try:
            risky_ports = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                53: 'DNS', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
                1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL',
                6379: 'Redis', 27017: 'MongoDB'
            }

            tasks = []
            for port, service in risky_ports.items():
                tasks.append(self._check_port(target, port, service))

            port_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in port_results:
                if result and not isinstance(result, Exception):
                    port, service, is_open = result
                    if is_open:
                        results['open_ports'].append(
                            {'port': port, 'service': service})

                        severity = 'HIGH' if port in [
                            23, 21, 135, 139] else 'MEDIUM'
                        vuln = {
                            'type': 'Open Port',
                            'severity': severity,
                            'title': f'{service} Service Exposed',
                            'description': f'{service} service running on port {port}',
                            'port': port,
                            'service': service,
                            'recommendation': f'Secure {service} service or restrict access'}
                        self.vulnerabilities.append(vuln)

        except Exception:
            pass

    async def _check_port(self, target: str, port: int, service: str) -> tuple:
        """Check if a specific port is open."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=3
            )
            writer.close()
            await writer.wait_closed()
            return (port, service, True)
        except BaseException:
            return (port, service, False)

    def get_plugin_info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.plugin_type,
            "version": "1.0.0",
            "checks": "SSL/TLS, Security Headers, Directory Traversal, SQL Injection, XSS, Open Ports, CMS Detection"
        }
