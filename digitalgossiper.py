#!/usr/bin/env python3

import asyncio
import ssl
import socket
import re
import json
from typing import Dict, List, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree
from rich import box
from rich.style import Style

console = Console()

class DigitalGossiper:
    def __init__(self, rate_limit: float = 0.5, timeout: int = 10):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.session = None
        self.results = {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        # Common spots that tend to be interesting
        self.common_paths = [
            "admin", "login", "api", "config", "backup", "test", "dev", "debug", "logs",
            "dashboard", "console", "cgi-bin", "manager", "install", "upload", "static",
            "assets", "public", "private", "env", "settings", "database", "docs", "readme",
            "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml"
        ]

    async def create_session(self):
        # Spin up an aiohttp session with timeout + rate control...
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout, sock_connect=self.timeout, sock_read=self.timeout)
        connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=5,
            ssl=False,
            ttl_dns_cache=300,
        )
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=self.headers,
            raise_for_status=False
        )

    async def close_session(self):
        """Close aiohttp session properly"""
        if self.session and not self.session.closed:
            await self.session.close()

    #== EXTENDED RECONNAISSANCE FUNCTIONS

    def _extract_technology(self, headers: Dict, body: str, url: str) -> Dict:
        # Pull out detected technologies, versions and some context
        tech = {
            'web_server': None,
            'backend': None,
            'frontend': set(),
            'cms': None,
            'database': None,
            'versions': {}
        }

        server = headers.get('server', '').lower()
        if 'apache' in server:
            tech['web_server'] = 'Apache'
        elif 'nginx' in server:
            tech['web_server'] = 'Nginx'
        elif 'iis' in server or 'microsoft' in server:
            tech['web_server'] = 'Microsoft IIS'
        elif 'cloudflare' in server:
            tech['web_server'] = 'Cloudflare (CDN)'

        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech['backend'] = 'PHP'
        elif 'asp.net' in powered_by:
            tech['backend'] = 'ASP.NET'
        elif 'express' in powered_by:
            tech['backend'] = 'Node.js/Express'
        elif 'python' in powered_by or 'wsgi' in powered_by:
            tech['backend'] = 'Python'

        body_lower = body.lower()
        if 'react' in body_lower:
            tech['frontend'].add('React')
        if 'vue' in body_lower:
            tech['frontend'].add('Vue.js')
        if 'angular' in body_lower and 'angularjs' not in body_lower:
            tech['frontend'].add('Angular')

        if 'wordpress' in body_lower:
            tech['cms'] = 'WordPress'

        return tech

    def _detect_waf(self, headers: Dict, body: str) -> Optional[Dict]:
        # Detect WAF and estimate its protection level
        header_str = str(headers).lower()

        if 'cf-ray' in header_str or 'cloudflare' in header_str:
            return {
                'name': 'Cloudflare',
                'protection_level': 'high',
                'type': 'CDN+WAF',
                'confidence': 'high'
            }
        elif 'x-amz-cf-id' in headers or 'cloudfront' in header_str:
            return {
                'name': 'AWS CloudFront',
                'protection_level': 'medium',
                'type': 'CDN+WAF',
                'confidence': 'medium'
            }

        return None

    def _detect_cdn(self, headers: Dict) -> Optional[Dict]:
        # Check for edge network shielding
        header_str = str(headers).lower()

        if 'cf-ray' in header_str or 'cloudflare' in header_str:
            return {'name': 'Cloudflare', 'type': 'Full Proxy', 'features': []}
        elif 'x-amz-cf-id' in headers or 'cloudfront' in header_str:
            return {'name': 'CloudFront', 'type': 'AWS CDN', 'features': []}

        return None

    def _analyze_cookies(self, headers: Dict) -> Dict:
        #Analyze cookies with security flags
        cookies_analysis = {
            'raw_cookies': {},
            'session_cookies': [],
            'tracking_cookies': [],
            'security_cookies': [],
            'internal_cookies': [],
            'security_flags': {
                'secure': 0,
                'httponly': 0,
                'samesite': 0,
                'missing_flags': 0
            },
            'total_count': 0
        }

        if 'set-cookie' in headers:
            cookie_headers = headers['set-cookie']
            if isinstance(cookie_headers, str):
                cookie_headers = [cookie_headers]

            for cookie_header in cookie_headers:
                cookies_analysis['total_count'] += 1
                cookie_parts = cookie_header.split(';')

                if cookie_parts:
                    first_part = cookie_parts[0]
                    if '=' in first_part:
                        key, value = first_part.split('=', 1)
                        cookie_name = key.strip()
                        cookies_analysis['raw_cookies'][cookie_name] = value.strip()

                        cookie_lower = cookie_name.lower()
                        if any(x in cookie_lower for x in ['session', 'sid', 'token', 'auth']):
                            cookies_analysis['session_cookies'].append(cookie_name)
                        elif any(x in cookie_lower for x in ['backend', 'internal', 'admin', 'debug']):
                            cookies_analysis['internal_cookies'].append(cookie_name)

        return cookies_analysis

    def _analyze_csp(self, headers: Dict) -> Optional[Dict]:
        #Analyze CSP
        if 'content-security-policy' not in headers:
            return None

        csp_header = headers['content-security-policy']
        directives = {}
        parts = csp_header.split(';')

        for part in parts:
            if part.strip():
                directive_parts = part.strip().split(' ', 1)
                if len(directive_parts) == 2:
                    directive, value = directive_parts
                    directives[directive.strip()] = value.strip()

        security_score = 0
        if 'default-src' in directives:
            security_score += 2
        if 'script-src' in directives:
            security_score += 2

        if security_score >= 3:
            level = 'strict'
        elif security_score >= 2:
            level = 'moderate'
        else:
            level = 'weak'

        return {
            'raw_policy': csp_header,
            'directives': directives,
            'security_score': security_score,
            'max_score': 5,
            'level': level
        }

    def _analyze_ssl_cert(self, hostname: str) -> Optional[Dict]:
        #Analyze SSL certificate with robust error handling
        try:
            hostname_clean = hostname.split(':')[0]
            try:
                socket.gethostbyname(hostname_clean)
            except socket.gaierror as e:
                console.print(f"[yellow]DNS resolution failed for {hostname_clean}: {e}[/yellow]")
                return None

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname_clean, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname_clean) as ssock:
                    cert_bin = ssock.getpeercert(True)
                    if cert_bin:
                        # Note: Removed cryptography dependency for simplicity
                        # This is a simplified SSL analysis
                        return {
                            'issuer': 'Unknown (cryptography module not available)',
                            'sans_count': 0,
                            'sans': [],
                            'surface_assessment': 'limited'
                        }
        except Exception as e:
            console.print(f"[yellow]SSL error for {hostname}: {e}[/yellow]")
            return None

        return None

    async def _enumerate_paths(self, base_url: str) -> Dict:
        #Enumerate common paths
        found_paths = {}
        base_parsed = urlparse(base_url)
        base_netloc = base_parsed.netloc

        tasks = []
        for path in self.common_paths:
            full_url = urljoin(base_url, path)
            tasks.append(self._check_path(full_url, path))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for path, res in zip(self.common_paths, results):
            if isinstance(res, dict):
                found_paths[path] = res

        return {'paths': found_paths}

    async def _check_path(self, full_url: str, path: str) -> Optional[Dict]:
        """Check if a path exists"""
        try:
            async with self.session.head(full_url, allow_redirects=True) as response:
                if response.status in [200, 301, 302, 403, 405]:
                    return {
                        'path': path,
                        'url': full_url,
                        'status': response.status,
                        'redirected_to': str(response.real_url) if response.real_url != full_url else None
                    }
        except Exception:
            pass
        return None

    async def _analyze_structure(self, base_url: str, body: str) -> Dict:
        #Now we try to understand how this thing thinks
        structure = {
            'login_endpoints': [],
            'api_endpoints': [],
            'admin_pages': [],
            'external_domains': [],
            'sensitive_files': [],
            'js_scripts': [],
            'comments': [],
        }

        # find possible login/admin endpoints.
        login_patterns = [r'/login', r'/signin', r'/auth', r'/account', r'/dashboard']
        for pattern in login_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                structure['login_endpoints'].append(pattern)

        # Find API endpoints
        api_patterns = [r'/api/', r'/rest/', r'/graphql']
        for pattern in api_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            structure['api_endpoints'].extend(matches)

        # # Hunt for juicy HTML comments
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, body, re.DOTALL)
        structure['comments'] = [c.strip() for c in comments if c.strip()]

        # Find JS scripts
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        js_matches = re.findall(script_pattern, body, re.IGNORECASE)
        for js_url in js_matches:
            abs_url = urljoin(base_url, js_url)
            structure['js_scripts'].append(abs_url)

        # Find external domains in scripts and hrefs
        domain_pattern = r'https?://(?:[-\w.])+(?:\:[0-9]+)?'
        domains = re.findall(domain_pattern, body, re.IGNORECASE)
        unique_domains = list(set(domains))
        structure['external_domains'] = [d for d in unique_domains if base_url not in d]

        return structure

    def _extract_from_js(self, js_content: str) -> Dict:
        #Extract endpoints, keys, domains from JS
        extracted = {
            'endpoints': [],
            'api_keys': [],
            'internal_domains': [],
        }
        # Scan JS for interesting patterns
        endpoint_pattern = r'[\'"`](/api/[^\'"`\s]+|/rest/[^\'"`\s]+|/v\d+/[^\'"`\s]+)[\'"`]'
        key_pattern = r'(?:key|token|secret)["\s:]+=["\s]*["\'](.*?)(?=["\'])'
        domain_pattern = r'(?:https?://[^/\s\'"`]+)'

        extracted['endpoints'] = re.findall(endpoint_pattern, js_content, re.IGNORECASE)
        extracted['api_keys'] = re.findall(key_pattern, js_content)
        extracted['internal_domains'] = re.findall(domain_pattern, js_content)

        return extracted

    async def _download_js_and_analyze(self, js_urls: List[str]) -> Dict:
        """Download and analyze JS to extract logic"""
        all_extracted = {
            'endpoints': set(),
            'api_keys': set(),
            'internal_domains': set(),
        }

        tasks = []
        for url in js_urls:
            tasks.append(self._fetch_and_parse_js(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, dict):
                all_extracted['endpoints'].update(res.get('endpoints', []))
                all_extracted['api_keys'].update(res.get('api_keys', []))
                all_extracted['internal_domains'].update(res.get('internal_domains', []))

        return {k: list(v) for k, v in all_extracted.items()}

    async def _fetch_and_parse_js(self, url: str) -> Optional[Dict]:
        """Fetch and analyze a JS file"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    return self._extract_from_js(content)
        except Exception:
            pass
        return {}

    def _get_ip(self, hostname: str) -> Optional[str]:
        #Get IP from hostname
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    async def scan_target(self, url: str) -> Optional[Dict]:
        #Run the scan without crashing on every hiccup
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'https://' + url

        hostname = urlparse(url).netloc.split(':')[0]
        console.print(f"\n[bold cyan]Analyzing: {url}[/bold cyan]")

        try:
            async with self.session.get(url, allow_redirects=True) as response:
                body = await response.text()
                headers = dict(response.headers)

                # Extract IP
                ip_address = self._get_ip(hostname)

                #Extract intelligence.
                tech = self._extract_technology(headers, body, url)
                waf = self._detect_waf(headers, body)
                cdn = self._detect_cdn(headers)
                cookies = self._analyze_cookies(headers)
                csp = self._analyze_csp(headers)
                ssl_cert = self._analyze_ssl_cert(hostname)
                structure = await self._analyze_structure(url, body)

                # Enumerate paths
                paths_enum = await self._enumerate_paths(url)

                # Analyze JS
                js_analysis = await self._download_js_and_analyze(structure['js_scripts'])

                return {
                    'url': url,
                    'status_code': response.status,
                    'ip': ip_address,
                    'technology': tech,
                    'waf': waf,
                    'cdn': cdn,
                    'cookies': cookies,
                    'csp': csp,
                    'ssl_cert': ssl_cert,
                    'structure': structure,
                    'paths_enum': paths_enum,
                    'js_analysis': js_analysis
                }

        except aiohttp.ClientConnectorError as e:
            console.print(f"[bold red]Connection failed with {url}: {e}[/bold red]")
            return None
        except aiohttp.ClientResponseError as e:
            console.print(f"[bold yellow]HTTP Error {e.status} on {url}[/bold yellow]")
            return None
        except asyncio.TimeoutError:
            console.print(f"[bold red]Timeout scanning {url}[/bold red]")
            return None
        except Exception as e:
            console.print(f"[bold red]Unexpected error on {url}: {type(e).__name__}: {e}[/bold red]")
            return None

    def display_results(self, results: Dict):
        #Display extended results----
        if not results:
            return

        url = results['url']
        ip = results.get('ip', 'N/A')
        tech = results['technology']
        paths = results['paths_enum']['paths']
        structure = results['structure']
        js_analysis = results['js_analysis']

        # Display in compact format
        status = f"[{results['status_code']}]"
        server_version = tech.get('web_server', 'Unknown Server')
        server_info = f"[{server_version}]"

        # Heuristically infer the application identity
        app_name = "Unknown App"
        if "Keep On" in str(results.get('structure', {})):
            app_name = "Keep On - Portal"
        app_info = f"[{app_name}]"

        # Detect technologies and providers
        tech_list = list(tech.get('frontend', []))
        if tech.get('web_server'):
            tech_list.append(tech['web_server'])
        if js_analysis.get('endpoints'):
            tech_list.append("JS Endpoints Found")
        # Infer basic provider
        provider = []
        if 'Azure' in str(results.get('cdn', {})):
            provider.append('Azure')
        if 'Cloudflare' in str(results.get('cdn', {})):
            provider.append('Cloudflare')
        if 'Imperva' in str(results.get('waf', {}) or {}):
            provider.append('Imperva')

        combined_tech = list(set(provider + tech_list))
        tech_info = f"[{','.join(combined_tech) if combined_tech else 'Unknown Techs'}]"

        print(f"{url}   {status} {app_info} {server_info} {tech_info}")
        print(f"     └─ IP: {ip}")

        # Display logical structure
        console.print("\n[bold blue]Detected Logical Structure:[/bold blue]")
        struct_tree = Tree("Internal Structure")

        if structure['login_endpoints']:
            login_node = struct_tree.add("Login/Admin Endpoints")
            for ep in structure['login_endpoints']:
                login_node.add(ep)

        if structure['api_endpoints']:
            api_node = struct_tree.add("API Endpoints")
            for ep in set(structure['api_endpoints']):
                api_node.add(ep)

        if structure['js_scripts']:
            js_node = struct_tree.add("External JS Scripts")
            for js in structure['js_scripts'][:5]:  # Limit quantity
                js_node.add(js)

        if js_analysis.get('endpoints'):
            js_ep_node = struct_tree.add("Endpoints from JS")
            for ep in js_analysis['endpoints'][:5]:
                js_ep_node.add(ep)

        if structure['external_domains']:
            ext_node = struct_tree.add("External Domains")
            for dom in structure['external_domains'][:5]:
                ext_node.add(dom)

        if paths:
            paths_node = struct_tree.add("Discovered Paths")
            for path, data in list(paths.items())[:10]:  # Limit quantity
                paths_node.add(f"{data['url']} -> {data['status']}")

        console.print(struct_tree)

    async def run(self, targets: List[str]):
        #Execute scan with error handling
        await self.create_session()

        try:
            for target in targets:
                result = await self.scan_target(target)
                if result:
                    self.results[target] = result
                    self.display_results(result)
                else:
                    console.print(f"[bold yellow]Skipping {target} (analysis error)[/bold yellow]\n")

        finally:
            await self.close_session()


async def main():
    #Main function with argument handling
    import sys

    console.print("\n[bold cyan]DigitalGossiper v4.0 - Advanced Web Reconnaissance Engine[/bold cyan]\n")

    if len(sys.argv) > 1:
        targets = [arg.strip() for arg in sys.argv[1:] if arg.strip()]
    else:
        console.print("[bold yellow]Enter domains (one per line, Ctrl+D to finish):[/bold yellow]\n")
        targets = []
        try:
            while True:
                line = input("> ").strip()
                if line:
                    targets.append(line)
        except EOFError:
            pass

    if not targets:
        console.print("[bold red]No targets provided[/bold red]")
        console.print("\n[bold]Usage:[/bold]")
        console.print("  python digitalgossiper_v4.py example.com")
        return

    gossiper = DigitalGossiper(rate_limit=0.5, timeout=10)
    await gossiper.run(targets)

    console.print(f"\n[bold green]Analysis completed.[/bold green]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Analysis interrupted by user[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
        import traceback
        traceback.print_exc()
