#!/usr/bin/env python3
"""
FireThief - Prometheus Security Scanner
"Stealing fire from the Titans" - Comprehensive Prometheus/Go debug endpoint analysis

Based on research from:
- Aqua Security (300K+ exposed instances, Dec 2024)
- CyberSRC (Credential leakage patterns)
- Sysdig (Kubernetes exploitation via Prometheus)
- Red Sentry (Go pprof exploitation techniques)
"""

import argparse
import re
import sys
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Tuple, Set
import gzip
from io import BytesIO
import json
import subprocess
import tempfile
import os
from pathlib import Path
from datetime import datetime
import threading
import time

from patterns import CREDENTIAL_RULES, compile_patterns
from web import create_web_ui

requests.packages.urllib3.disable_warnings()

BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗██╗██████╗ ███████╗████████╗██╗  ██╗██╗███████╗███████╗       ║
║   ██╔════╝██║██╔══██╗██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔════╝       ║
║   █████╗  ██║██████╔╝█████╗     ██║   ███████║██║█████╗  █████╗         ║
║   ██╔══╝  ██║██╔══██╗██╔══╝     ██║   ██╔══██║██║██╔══╝  ██╔══╝         ║
║   ██║     ██║██║  ██║███████╗   ██║   ██║  ██║██║███████╗██║            ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚═╝            ║
║                                                                           ║
║              "Stealing fire from the Titans"                             ║
║          Prometheus Security Assessment Framework                        ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

class PrometheusScanner:
    def __init__(self, host: str, port: int, timeout: int = 10, verbose: bool = False,
                 save_profiles: bool = False, output_dir: str = None, scheme: str = 'http'):
        self.host = host
        self.port = port
        self.base_url = f"{scheme}://{host}:{port}"
        self.timeout = timeout
        self.verbose = verbose
        self.save_profiles = save_profiles
        self.output_dir = output_dir or f"firethief_{host}_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if self.save_profiles:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            print(f"[+] Output directory: {self.output_dir}")
        
        self.scan_start = datetime.now()
        self.scan_end = None
        self.scan_status = "initializing"
        self.current_phase = ""
        self.current_action = ""
        self.progress_percent = 0
        
        self.findings = {
            'secrets': [],
            'fqdns': [],
            'urls': [],
            'containers': [],
            'k8s': [],
            'credentials': [],
            'internal_routes': [],
            'dos_vectors': [],
            'config_exposure': [],
            'scrape_targets': [],
            'discovered_endpoints': [],
            'accessible_endpoints': [],
            'infrastructure': {
                'deployment_type': None,
                'deployment_signals': [],
                'prometheus_version': None,
                'storage_retention': None,
                'resource_limits': {},
                'colocation': [],
                'operator': None,
                'operator_signals': [],
                'ha_setup': None,
                'ha_signals': [],
                'node_info': {},
            }
        }

        self._infra_raw = {}
        self._seen_credentials = set()  # Global dedup: (type, value) pairs

        self.endpoints = self._get_discovery_endpoints()
        self.patterns = compile_patterns()
        
        self.has_go_pprof = self._check_go_pprof()
        if not self.has_go_pprof:
            print("[!] WARNING: 'go tool pprof' not found. Profile decoding will be limited.")
            print("[!] Install Go to enable full pprof analysis: https://go.dev/dl/")
            print("[!] After installing Go, you may need to install pprof:")
            print("[!]   go install github.com/google/pprof@latest")
    
    def update_status(self, phase: str, action: str = "", percent: int = 0):
        self.current_phase = phase
        self.current_action = action
        self.progress_percent = percent
        if self.verbose and action:
            print(f"[*] {action}")
    
    # Placeholder/test values that should never be reported as real credentials
    PLACEHOLDER_BLOCKLIST = {
        'changeme', 'change_me', 'example', 'placeholder', 'redacted',
        'your_key_here', 'your_token_here', 'your_secret_here', 'your_api_key',
        'insert_key_here', 'insert_token_here', 'xxx', 'xxxx', 'xxxxx',
        'test', 'testing', 'dummy', 'fake', 'sample', 'demo', 'default',
        'none', 'null', 'undefined', 'todo', 'fixme', 'replace_me',
        'password', 'password123', 'admin', 'secret', 'token',
        'abcdef', 'abcdefgh', '12345678', '123456789', '1234567890',
        'aaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbb', '0000000000000000',
        'ffffffffffffffff', 'deadbeef', 'cafebabe',
    }

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string. Higher = more random = more likely real."""
        import math
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _is_placeholder(self, value: str) -> bool:
        """Check if a credential value is a known placeholder or test value."""
        normalized = value.lower().strip().rstrip('.')
        if normalized in self.PLACEHOLDER_BLOCKLIST:
            return True
        # Check for repeated characters (e.g., 'aaaaaa', '000000')
        if len(set(normalized)) <= 2 and len(normalized) >= 8:
            return True
        # Check for sequential patterns
        if normalized in ('abcdefghijklmnop', '0123456789abcdef'):
            return True
        return False

    def _dedup_credential(self, cred_type: str, value: str) -> bool:
        """Return True if this credential was already seen (is a duplicate)."""
        key = (cred_type, value)
        if key in self._seen_credentials:
            return True
        self._seen_credentials.add(key)
        return False

    def _check_go_pprof(self) -> bool:
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, timeout=5)
            if result.returncode != 0:
                return False
            
            result = subprocess.run(['go', 'tool', 'pprof', '-h'], 
                                   capture_output=True, timeout=5)
            if result.returncode == 0:
                return True
            
            print("[!] Go is installed but 'go tool pprof' is not available")
            print("[!] You may need to install it with: go install github.com/google/pprof@latest")
            return False
            
        except FileNotFoundError:
            return False
        except Exception:
            return False
    
    def _get_discovery_endpoints(self) -> List[str]:
        return [
            '/debug/pprof/',
            '/metrics',
            '/',
            '/graph',
            '/targets',
            '/api/v1/status/config',
            '/api/v1/status/flags',
        ]
    
    def _get_full_endpoints(self) -> List[str]:
        return [
            '/debug/pprof/',
            '/debug/pprof/heap',
            '/debug/pprof/profile?seconds=5',
            '/debug/pprof/goroutine?debug=1',
            '/debug/pprof/goroutine?debug=2',
            '/debug/pprof/threadcreate',
            '/debug/pprof/block',
            '/debug/pprof/mutex',
            '/debug/pprof/allocs',
            '/debug/pprof/trace?seconds=5',
            '/debug/pprof/cmdline',
            '/debug/pprof/symbol',
            '/debug/vars',
            '/debug/config',
            '/debug/flags',
            '/debug/fgprof',
            '/debug/requests',
            '/debug/events',
            '/metrics',
            '/federate',
            '/api/v1/status/config',
            '/api/v1/status/flags',
            '/api/v1/status/runtimeinfo',
            '/api/v1/status/buildinfo',
            '/api/v1/targets',
            '/api/v1/targets/metadata',
            '/api/v1/alertmanagers',
            '/api/v1/labels',
            '/api/v1/label/__name__/values',
            '/api/v1/series?match[]=up',
            '/api/v1/query?query=up',
            '/api/v1/rules',
            '/alertmanager/api/v2/status',
            '/alertmanager/api/v2/silences',
            '/alertmanager/api/v2/alerts',
            '/graph',
            '/targets',
            '/service-discovery',
            '/config',
            '/flags',
            '/status',
            '/tsdb-status',
            '/-/healthy',
            '/-/ready',
            '/api/v1/metrics',
        ]
    
    def is_valid_fqdn(self, domain: str) -> bool:
        domain = domain.rstrip('.')
        
        if '.' not in domain:
            return False
        
        parts = domain.split('.')
        
        if len(parts) < 2:
            return False
        
        false_positives = {
            'fmt.println', 'fmt.sprintf', 'fmt.printf', 'fmt.print',
            'log.info', 'log.debug', 'log.error', 'log.warn', 'log.fatal',
            'console.log', 'console.error', 'console.warn', 'console.debug',
            'system.out', 'system.err',
            'std.cout', 'std.cerr',
            'main.go', 'main.main', 'handler.go', 'server.go',
            'app.run', 'app.listen', 'app.get', 'app.post',
            'db.query', 'db.exec', 'db.prepare',
            'http.get', 'http.post', 'http.request',
            'os.getenv', 'os.environ', 'os.path',
            'json.marshal', 'json.unmarshal', 'json.loads', 'json.dumps',
            'index.html', 'main.css', 'app.js', 'style.css',
            'config.yaml', 'config.json', 'settings.ini',
            'job.name', 'instance.name', 'node.name',
            'status.code', 'http.status', 'response.time',
            'request.duration', 'error.count',
            'v1.0', 'v2.0', 'v1.2', 'version.1',
            'user.name', 'first.last', 'admin.user',
            'test.test', 'example.example',
            'localhost.localdomain',
        }
        
        domain_lower = domain.lower()
        if domain_lower in false_positives:
            return False
        
        if any(pattern in domain_lower for pattern in [
            '//', '\\\\', '..', 
            'function.', 'method.', 'class.',
            'package.', 'module.',
        ]):
            return False
        
        for part in parts:
            if not part:
                return False
            
            if len(part) > 63:
                return False
            
            if not (part[0].isalnum() and part[-1].isalnum()):
                return False
            
            if not all(c.isalnum() or c == '-' for c in part):
                return False
        
        tld = parts[-1].lower()
        
        if len(tld) < 2:
            return False
        
        if tld.isdigit():
            return False
        
        if len(tld) == 1:
            return False
        
        file_extensions = {
            'go', 'py', 'js', 'ts', 'c', 'cpp', 'h', 'hpp',
            'java', 'class', 'jar', 'war',
            'rb', 'php', 'pl', 'sh', 'bash',
            'html', 'htm', 'css', 'scss', 'sass',
            'json', 'xml', 'yaml', 'yml', 'toml', 'ini',
            'txt', 'md', 'rst', 'pdf', 'doc', 'docx',
            'log', 'out', 'err',
            'sql', 'db', 'sqlite',
            'tar', 'gz', 'zip', 'rar', 'bz2',
            'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico',
            'mp3', 'mp4', 'avi', 'mov', 'wav',
        }
        
        if tld in file_extensions:
            return False
        
        if len(parts) == 2:
            first_part = parts[0].lower()
            
            code_patterns = [
                'func', 'function', 'var', 'const', 'let',
                'main', 'init', 'test', 'handler', 'server',
                'get', 'post', 'put', 'delete', 'patch',
                'create', 'read', 'update', 'delete',
                'start', 'stop', 'run', 'exec',
                'print', 'println', 'printf', 'sprintf',
            ]
            
            if first_part in code_patterns:
                return False
        
        return True
    
    def discover_endpoints(self) -> List[str]:
        discovered = []
        
        self.update_status("discovery", "Starting endpoint discovery...", 5)
        print("\n[*] PHASE 1: ENDPOINT DISCOVERY")
        print("="*80)
        
        self.update_status("discovery", "Checking /debug/pprof/...", 10)
        success, content, _, _ = self.scan_endpoint('/debug/pprof/')
        if success:
            print("[+] /debug/pprof/ accessible - parsing index")
            text = content.decode('utf-8', errors='ignore')
            
            pprof_pattern = re.compile(r'href="(/debug/pprof/[^"]+)"')
            for match in pprof_pattern.finditer(text):
                endpoint = match.group(1)
                base_endpoint = endpoint.split('?')[0]
                if base_endpoint not in discovered:
                    discovered.append(base_endpoint)
                    self.findings['discovered_endpoints'].append(base_endpoint)
                    print(f"  [+] Discovered: {base_endpoint}")
            
            for endpoint in ['/debug/pprof/heap', '/debug/pprof/profile', 
                           '/debug/pprof/goroutine', '/debug/pprof/allocs']:
                if endpoint not in discovered:
                    discovered.append(endpoint)
                    discovered.append(f"{endpoint}?debug=1")
                    discovered.append(f"{endpoint}?debug=2")
        
        self.update_status("discovery", "Checking Prometheus API...", 15)
        success, content, _, _ = self.scan_endpoint('/api/v1/status/config')
        if success:
            print("[+] Prometheus API accessible")
            for endpoint in ['/api/v1/targets', '/api/v1/labels', '/api/v1/rules',
                           '/api/v1/series?match[]=up', '/api/v1/alertmanagers']:
                if endpoint not in discovered:
                    discovered.append(endpoint)
                    self.findings['discovered_endpoints'].append(endpoint)
        
        self.update_status("discovery", "Checking main UI...", 20)
        success, content, _, _ = self.scan_endpoint('/')
        if success:
            text = content.decode('utf-8', errors='ignore')
            link_pattern = re.compile(r'href="(/[^"]+)"')
            for match in link_pattern.finditer(text):
                endpoint = match.group(1)
                if endpoint.startswith('/') and endpoint not in discovered:
                    if not any(x in endpoint for x in ['.js', '.css', '.png', '.ico']):
                        discovered.append(endpoint)
        
        self.update_status("discovery", f"Discovery complete: {len(discovered)} endpoints found", 25)
        print(f"[+] Discovery complete: {len(discovered)} endpoints found\n")
        return discovered
    
    def download_profile(self, endpoint: str, profile_type: str) -> Tuple[bool, bytes, str]:
        url = urljoin(self.base_url, endpoint)
        
        try:
            if self.verbose:
                print(f"[*] Downloading profile: {url}")
            
            resp = self._http_get(url, timeout=30)
            
            if resp.status_code == 200:
                content = resp.content
                
                if self.save_profiles:
                    safe_name = profile_type.replace('/', '_').replace('?', '_')
                    filename = f"{safe_name}.pb.gz"
                    filepath = os.path.join(self.output_dir, filename)
                    
                    with open(filepath, 'wb') as f:
                        f.write(content)
                    
                    if self.verbose:
                        print(f"  [+] Saved to: {filepath}")
                    
                    return True, content, filepath
                
                return True, content, ""
            
            return False, b'', ""
        
        except Exception as e:
            if self.verbose:
                print(f"[-] Error downloading profile: {e}")
            return False, b'', ""
    
    def decode_profile_with_pprof(self, profile_data: bytes, profile_type: str) -> str:
        if not self.has_go_pprof:
            return ""
        
        try:
            with tempfile.NamedTemporaryFile(suffix='.pb.gz', delete=False) as tmp:
                tmp.write(profile_data)
                tmp_path = tmp.name
            
            cmd = ['go', 'tool', 'pprof', '-text', tmp_path]
            result = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
            
            os.unlink(tmp_path)
            
            if result.returncode == 0:
                decoded = result.stdout
                
                if self.save_profiles:
                    safe_name = profile_type.replace('/', '_').replace('?', '_')
                    filename = f"{safe_name}_decoded.txt"
                    filepath = os.path.join(self.output_dir, filename)
                    
                    with open(filepath, 'w') as f:
                        f.write(decoded)
                    
                    if self.verbose:
                        print(f"  [+] Decoded profile saved: {filepath}")
                
                return decoded
            
            return ""
        
        except Exception as e:
            if self.verbose:
                print(f"[-] Error decoding profile with pprof: {e}")
            return ""
    
    def analyze_pprof_profile(self, endpoint: str, profile_type: str):
        self.update_status("pprof", f"Analyzing {endpoint}...", self.progress_percent)
        print(f"[*] Analyzing pprof profile: {endpoint}")
        
        success, content, filepath = self.download_profile(endpoint, profile_type)
        
        if not success:
            print(f"[-] Failed to download {endpoint}")
            return
        
        print(f"[+] Downloaded {len(content)} bytes")
        
        try:
            decompressed = gzip.decompress(content)
            print(f"[*] Analyzing decompressed binary data ({len(decompressed)} bytes)")
            self.analyze_content(decompressed, endpoint)
        except:
            print(f"[*] Analyzing raw binary data ({len(content)} bytes)")
            self.analyze_content(content, endpoint)
        
        if self.has_go_pprof:
            print(f"[*] Decoding with 'go tool pprof'...")
            decoded = self.decode_profile_with_pprof(content, profile_type)
            
            if decoded:
                print(f"[+] Successfully decoded {len(decoded)} bytes of text")
                print(f"[*] Analyzing decoded text for secrets...")
                self.analyze_content(decoded.encode('utf-8'), f"{endpoint}_decoded")
            else:
                print(f"[-] Failed to decode profile")

    def _http_get(self, url: str, timeout: int = None) -> requests.Response:
        return requests.get(url, timeout=timeout or self.timeout,
                            verify=False, allow_redirects=True)

    def scan_endpoint(self, endpoint: str) -> Tuple[bool, bytes, str, dict]:
        url = urljoin(self.base_url, endpoint)
        try:
            if self.verbose:
                print(f"[*] Scanning: {url}")
            resp = self._http_get(url)

            if resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '')
                return True, resp.content, content_type, dict(resp.headers)

            return False, b'', '', {}

        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[-] Error accessing {url}: {e}")
            return False, b'', '', {}
    
    def check_dos_vectors(self, endpoint: str, headers: dict):
        if '/debug/pprof/' in endpoint:
            auth_header = headers.get('WWW-Authenticate', '')
            if not auth_header:
                self.findings['dos_vectors'].append({
                    'endpoint': endpoint,
                    'issue': 'Unauthenticated pprof endpoint (DoS via CPU/heap profiling)',
                    'reference': 'Aqua: 300K+ instances vulnerable to DoS',
                    'severity': 'HIGH'
                })
    
    def analyze_prometheus_config(self, content: bytes, endpoint: str):
        try:
            text = content.decode('utf-8', errors='ignore')
            
            if 'remote_write' in text or 'remote_read' in text:
                self.findings['config_exposure'].append({
                    'type': 'remote_storage_config',
                    'endpoint': endpoint,
                    'issue': 'Remote storage configuration exposed (may contain credentials)',
                    'severity': 'MEDIUM'
                })
            
            if 'alertmanagers' in text or 'alerting' in text:
                for match in self.patterns['basic_auth_url'].finditer(text):
                    self.findings['credentials'].append({
                        'type': 'alertmanager_url_with_auth',
                        'value': match.group(0),
                        'endpoint': endpoint,
                        'severity': 'CRITICAL'
                    })
            
            if 'scrape_configs' in text:
                self.findings['config_exposure'].append({
                    'type': 'scrape_configs_exposed',
                    'endpoint': endpoint,
                    'issue': 'Scrape configuration exposed',
                    'severity': 'HIGH'
                })
        
        except Exception as e:
            if self.verbose:
                print(f"[-] Error analyzing config: {e}")
    
    def analyze_targets(self, content: bytes, endpoint: str):
        try:
            if endpoint.endswith('/json') or b'{' in content[:100]:
                data = json.loads(content.decode('utf-8', errors='ignore'))
                
                if 'data' in data and 'activeTargets' in data.get('data', {}):
                    for target in data['data']['activeTargets']:
                        scrape_url = target.get('scrapeUrl', '')
                        labels = target.get('labels', {})
                        
                        self.findings['scrape_targets'].append({
                            'scrape_url': scrape_url,
                            'job': labels.get('job', ''),
                            'instance': labels.get('instance', ''),
                            'endpoint': endpoint,
                            'health': target.get('health', 'unknown')
                        })
                        
                        if scrape_url:
                            parsed = urlparse(scrape_url)
                            if parsed.hostname:
                                self.findings['fqdns'].append({
                                    'value': parsed.hostname,
                                    'endpoint': endpoint,
                                    'source': 'scrape_target'
                                })
        except:
            pass
    
    def analyze_content(self, content: bytes, endpoint: str):
        try:
            text = content.decode('utf-8', errors='ignore')
        except:
            text = str(content)

        content_type = "heap/stack" if "pprof" in endpoint else "endpoint"
        if self.verbose:
            print(f"[*] Analyzing {content_type} content from {endpoint} ({len(text)} chars)")

        for match in self.patterns['secret_keywords'].finditer(text):
            val = match.group(2)
            if self._is_placeholder(val):
                continue
            if self._shannon_entropy(val) < 2.5 and len(val) < 30:
                continue
            display_val = val[:50] + ('...' if len(val) > 50 else '')
            if self._dedup_credential('keyword_secret', display_val):
                continue
            self.findings['secrets'].append({
                'type': 'keyword_secret',
                'keyword': match.group(1),
                'value': display_val,
                'endpoint': endpoint,
                'severity': 'HIGH'
            })

        # Data-driven credential detection with entropy, placeholder, and dedup filtering
        # Patterns that have strong structural prefixes and don't need entropy checks
        ENTROPY_EXEMPT = {
            'aws_key', 'github_pat', 'github_oauth', 'github_app', 'github_refresh',
            'github_fine_grained', 'gitlab_pat', 'gitlab_runner', 'npm_token', 'pypi_token',
            'slack_bot_token', 'slack_user_token', 'slack_workspace', 'slack_webhook',
            'stripe_live_secret', 'stripe_test_secret', 'stripe_live_pub', 'stripe_restricted',
            'square_access', 'square_oauth', 'sendgrid_api', 'digitalocean_pat',
            'digitalocean_oauth', 'digitalocean_refresh', 'shopify_token', 'shopify_shared',
            'shopify_custom', 'shopify_private', 'mailgun_api', 'mailgun_signing',
            'newrelic_api', 'newrelic_insights', 'grafana_key', 'grafana_service_account',
            'gcp_api_key', 'azure_storage', 'discord_webhook', 'jwt',
            'ssh_private_key', 'ssh_private_key_full', 'pgp_private_key',
        }
        for pattern_key, cred_type, group_idx, truncate, severity in CREDENTIAL_RULES:
            if pattern_key not in self.patterns:
                continue
            for match in self.patterns[pattern_key].finditer(text):
                val = match.group(group_idx)
                # Placeholder check on raw value
                if self._is_placeholder(val):
                    continue
                # Entropy check for patterns without strong structural prefixes
                if pattern_key not in ENTROPY_EXEMPT:
                    if self._shannon_entropy(val) < 3.0 and len(val) < 50:
                        continue
                if truncate:
                    val = val[:truncate] + '...'
                # Global dedup
                if self._dedup_credential(cred_type, val):
                    continue
                self.findings['credentials'].append({
                    'type': cred_type, 'value': val,
                    'endpoint': endpoint, 'severity': severity
                })

        # Special cases with extra fields or dedup logic
        for match in self.patterns['ssh_private_key_full'].finditer(text):
            if not self._dedup_credential('SSH_PRIVATE_KEY', 'FULL PRIVATE KEY DETECTED'):
                self.findings['credentials'].append({
                    'type': 'SSH_PRIVATE_KEY', 'value': 'FULL PRIVATE KEY DETECTED',
                    'endpoint': endpoint, 'severity': 'CRITICAL',
                    'note': 'Complete SSH private key found in content'
                })

        for match in self.patterns['ssh_private_key'].finditer(text):
            if not self._dedup_credential('SSH_PRIVATE_KEY_HEADER', 'SSH PRIVATE KEY DETECTED'):
                self.findings['credentials'].append({
                    'type': 'SSH_PRIVATE_KEY_HEADER', 'value': 'SSH PRIVATE KEY DETECTED',
                    'endpoint': endpoint, 'severity': 'CRITICAL'
                })

        for match in self.patterns['api_token_header'].finditer(text):
            val = match.group(2)
            if self._is_placeholder(val):
                continue
            display_val = val[:30] + '...'
            if self._dedup_credential('API_TOKEN_HEADER', display_val):
                continue
            self.findings['credentials'].append({
                'type': 'API_TOKEN_HEADER', 'header': match.group(1),
                'value': display_val, 'endpoint': endpoint, 'severity': 'HIGH'
            })

        for match in self.patterns['k8s_sa_token'].finditer(text):
            val = match.group(1)[:30] + '...'
            if self._dedup_credential('K8S_SERVICE_ACCOUNT_TOKEN', val):
                continue
            self.findings['credentials'].append({
                'type': 'K8S_SERVICE_ACCOUNT_TOKEN', 'value': val,
                'endpoint': endpoint, 'severity': 'CRITICAL',
                'note': 'K8s SA token - can be used for cluster access'
            })

        for match in self.patterns['env_var_secret'].finditer(text):
            raw_val = match.group(2)
            if self._is_placeholder(raw_val):
                continue
            if self._shannon_entropy(raw_val) < 2.5 and len(raw_val) < 30:
                continue
            display_val = raw_val[:50] + '...'
            if self._dedup_credential('ENVIRONMENT_VARIABLE_SECRET', display_val):
                continue
            self.findings['credentials'].append({
                'type': 'ENVIRONMENT_VARIABLE_SECRET', 'variable': match.group(1),
                'value': display_val, 'endpoint': endpoint, 'severity': 'HIGH'
            })

        seen_fqdns = set()
        for match in self.patterns['fqdn'].finditer(text):
            fqdn = match.group(0).lower()
            
            if len(fqdn) > 4 and fqdn not in seen_fqdns and self.is_valid_fqdn(fqdn):
                seen_fqdns.add(fqdn)
                self.findings['fqdns'].append({
                    'value': fqdn,
                    'endpoint': endpoint,
                    'type': 'validated_fqdn'
                })
                
                if self.verbose:
                    print(f"  [+] Valid FQDN found: {fqdn}")
        
        for match in self.patterns['k8s_service_url'].finditer(text):
            self.findings['urls'].append({
                'value': match.group(0),
                'endpoint': endpoint,
                'type': 'kubernetes_service_url'
            })
        
        for match in self.patterns['internal_url'].finditer(text):
            self.findings['urls'].append({
                'value': match.group(0),
                'endpoint': endpoint,
                'type': 'internal_url'
            })
        
        for match in self.patterns['private_ip'].finditer(text):
            self.findings['fqdns'].append({
                'value': match.group(0),
                'endpoint': endpoint,
                'type': 'private_ip'
            })
        
        for match in self.patterns['k8s_namespace'].finditer(text):
            self.findings['k8s'].append({
                'type': 'namespace',
                'value': match.group(1),
                'endpoint': endpoint
            })
        
        for match in self.patterns['k8s_secret_ref'].finditer(text):
            self.findings['k8s'].append({
                'type': 'secret_reference',
                'value': match.group(1),
                'endpoint': endpoint,
                'note': 'K8s secret name - potential exploitation target'
            })
        
        for match in self.patterns['registry'].finditer(text):
            self.findings['containers'].append({
                'type': 'registry',
                'value': match.group(0),
                'endpoint': endpoint
            })
        
        for match in self.patterns['docker_image'].finditer(text):
            self.findings['containers'].append({
                'type': 'image',
                'value': match.group(0),
                'endpoint': endpoint
            })
        
        for match in self.patterns['route_handler'].finditer(text):
            route = match.group(1)
            if route and route not in ['/metrics', '/health', '/ready']:
                self.findings['internal_routes'].append({
                    'route': route,
                    'endpoint': endpoint,
                    'source': 'stack_trace'
                })
        
        for match in self.patterns['secret_paths'].finditer(text):
            self.findings['secrets'].append({
                'type': 'secret_file_path',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'MEDIUM'
            })
        
        for match in self.patterns['cert_files'].finditer(text):
            self.findings['secrets'].append({
                'type': 'certificate_or_key_file',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'MEDIUM'
            })
    
    def _format_bytes(self, nbytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(nbytes) < 1024.0:
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024.0
        return f"{nbytes:.1f} PB"

    def _get_infra_json(self, endpoint_key):
        for ep, content in self._infra_raw.items():
            if endpoint_key in ep:
                try:
                    data = json.loads(content.decode('utf-8', errors='ignore'))
                    return data.get('data', data)
                except:
                    pass
        return None

    def _get_infra_text(self, endpoint_key):
        for ep, content in self._infra_raw.items():
            if endpoint_key in ep:
                return content.decode('utf-8', errors='ignore')
        return None

    def analyze_infrastructure(self):
        infra = self.findings['infrastructure']
        self._analyze_build_and_runtime(infra)
        self._analyze_resources(infra)
        self._analyze_deployment_type(infra)
        self._analyze_colocation(infra)
        self._analyze_operator(infra)
        self._analyze_ha_setup(infra)

        if infra['deployment_type']:
            print(f"[+] Deployment type: {infra['deployment_type']} ({len(infra['deployment_signals'])} signals)")
        if infra['prometheus_version']:
            print(f"[+] Prometheus version: {infra['prometheus_version']}")
        if infra['ha_setup']:
            print(f"[+] HA setup detected: {infra['ha_setup']}")
        if infra['operator']:
            print(f"[+] Operator: {infra['operator']}")
        if infra['resource_limits']:
            print(f"[+] Resource metrics collected: {len(infra['resource_limits'])} metrics")
        if infra['colocation']:
            print(f"[+] Co-located services: {len(infra['colocation'])}")

    def _analyze_build_and_runtime(self, infra):
        build = self._get_infra_json('buildinfo')
        if build:
            infra['prometheus_version'] = build.get('version', None)
            infra['node_info']['goVersion'] = build.get('goVersion', None)
            infra['node_info']['GOOS'] = build.get('goOS', build.get('GOOS', None))
            infra['node_info']['GOARCH'] = build.get('goArch', build.get('GOARCH', None))

        runtime = self._get_infra_json('runtimeinfo')
        if runtime:
            infra['node_info']['GOMAXPROCS'] = runtime.get('GOMAXPROCS', None)
            infra['node_info']['goroutineCount'] = runtime.get('goroutineCount', None)
            infra['node_info']['CWD'] = runtime.get('CWD', None)
            infra['storage_retention'] = runtime.get('storageRetention', None)

    def _analyze_deployment_type(self, infra):
        k8s_score = 0
        vm_score = 0

        cwd = infra['node_info'].get('CWD', '')
        if cwd:
            if '/prometheus' in cwd or '/var/run' in cwd:
                k8s_score += 1
                infra['deployment_signals'].append(f"CWD suggests container: {cwd}")
            elif cwd.startswith(('/opt/', '/usr/local/', '/home/')):
                vm_score += 1
                infra['deployment_signals'].append(f"CWD suggests VM/bare metal: {cwd}")

        for f in self.findings['fqdns']:
            if '.svc.cluster.local' in f.get('value', ''):
                k8s_score += 2
                infra['deployment_signals'].append(f"K8s service FQDN: {f['value']}")
                break

        for t in self.findings['scrape_targets']:
            labels = t if isinstance(t, dict) else {}
            if labels.get('job', ''):
                job = labels['job']
                if any(kw in job.lower() for kw in ['kube', 'k8s', 'kubernetes', 'node-exporter']):
                    k8s_score += 1
                    infra['deployment_signals'].append(f"K8s-style scrape job: {job}")
                    break

        for item in self.findings['k8s']:
            if item.get('type') in ('namespace', 'pod', 'service', 'deployment'):
                k8s_score += 1
                infra['deployment_signals'].append(f"K8s metadata found: {item['type']}")
                break

        if self.findings['containers']:
            registries = [c for c in self.findings['containers'] if c.get('type') == 'registry']
            if registries:
                k8s_score += 1
                infra['deployment_signals'].append(f"Container registries detected: {len(registries)}")

        all_text = ' '.join(self._get_infra_text(ep) or '' for ep in
                            ['config', 'flags', 'runtimeinfo'])
        if '/var/run/secrets/kubernetes.io' in all_text:
            k8s_score += 2
            infra['deployment_signals'].append("K8s service account secrets path detected")
        if '/etc/systemd/' in all_text or 'systemd' in all_text.lower():
            vm_score += 1
            infra['deployment_signals'].append("systemd references detected")

        flags = self._get_infra_json('flags')
        if flags:
            config_file = flags.get('config.file', '')
            if '/etc/prometheus/' in config_file:
                if 'config_out' in config_file:
                    k8s_score += 1
                    infra['deployment_signals'].append(f"Operator-style config path: {config_file}")
                else:
                    vm_score += 1
                    infra['deployment_signals'].append(f"Traditional config path: {config_file}")

        if k8s_score > vm_score:
            infra['deployment_type'] = 'kubernetes'
        elif vm_score > k8s_score:
            infra['deployment_type'] = 'vm'
        else:
            infra['deployment_type'] = 'unknown'

    def _analyze_resources(self, infra):
        runtime = self._get_infra_json('runtimeinfo')
        if runtime:
            if runtime.get('GOMAXPROCS'):
                infra['resource_limits']['cpu_cores'] = runtime['GOMAXPROCS']
            if runtime.get('goroutineCount'):
                infra['resource_limits']['goroutines'] = runtime['goroutineCount']

        metrics_text = self._get_infra_text('metrics')
        if not metrics_text:
            return

        metric_patterns = {
            'resident_memory': r'process_resident_memory_bytes\s+([\d.e+]+)',
            'open_fds': r'process_open_fds\s+([\d.e+]+)',
            'max_fds': r'process_max_fds\s+([\d.e+]+)',
            'cpu_seconds': r'process_cpu_seconds_total\s+([\d.e+]+)',
            'go_alloc_bytes': r'go_memstats_alloc_bytes\{[^}]*\}\s+([\d.e+]+)|go_memstats_alloc_bytes\s+([\d.e+]+)',
            'tsdb_head_series': r'prometheus_tsdb_head_series\s+([\d.e+]+)',
        }

        for key, pattern in metric_patterns.items():
            match = re.search(pattern, metrics_text)
            if match:
                val_str = match.group(1) or (match.group(2) if match.lastindex >= 2 else None)
                if val_str:
                    val = float(val_str)
                    if key == 'resident_memory':
                        infra['resource_limits']['memory_bytes'] = int(val)
                        infra['resource_limits']['memory_human'] = self._format_bytes(val)
                    elif key == 'open_fds':
                        infra['resource_limits']['open_fds'] = int(val)
                    elif key == 'max_fds':
                        infra['resource_limits']['max_fds'] = int(val)
                    elif key == 'cpu_seconds':
                        infra['resource_limits']['cpu_seconds_total'] = round(val, 2)
                    elif key == 'go_alloc_bytes':
                        infra['resource_limits']['go_alloc_human'] = self._format_bytes(val)
                    elif key == 'tsdb_head_series':
                        infra['resource_limits']['tsdb_head_series'] = int(val)

    def _analyze_colocation(self, infra):
        for t in self.findings['scrape_targets']:
            scrape_url = t.get('scrape_url', '')
            if not scrape_url:
                continue
            try:
                parsed = urlparse(scrape_url)
                target_host = parsed.hostname
                if target_host and (target_host == self.host or
                                    target_host == 'localhost' or
                                    target_host == '127.0.0.1' or
                                    target_host == '::1'):
                    job = t.get('job', 'unknown')
                    if job != 'prometheus' and not any(c['job'] == job for c in infra['colocation']):
                        infra['colocation'].append({
                            'job': job,
                            'scrape_url': scrape_url,
                            'health': t.get('health', 'unknown')
                        })
            except:
                pass

    def _analyze_operator(self, infra):
        config_text = self._get_infra_text('config') or ''
        flags = self._get_infra_json('flags') or {}

        if 'serviceMonitor' in config_text or 'podMonitor' in config_text or 'probe' in config_text:
            infra['operator'] = 'prometheus-operator'
            infra['operator_signals'].append("serviceMonitor/podMonitor references in config")

        config_file = flags.get('config.file', '')
        if 'config_out' in config_file or 'prometheus-config-reloader' in config_text:
            infra['operator'] = 'prometheus-operator'
            infra['operator_signals'].append(f"Operator config path: {config_file}")

        for t in self.findings['scrape_targets']:
            job = t.get('job', '')
            if 'prometheus-operator' in job.lower() or 'kube-prometheus' in job.lower():
                infra['operator'] = 'prometheus-operator'
                infra['operator_signals'].append(f"Operator scrape job: {job}")
                break

        all_text = config_text + ' '.join(str(v) for v in flags.values())
        if 'helm.sh/chart' in all_text or 'app.kubernetes.io/managed-by' in all_text:
            if not infra['operator']:
                infra['operator'] = 'helm'
            infra['operator_signals'].append("Helm-managed deployment detected")

    def _analyze_ha_setup(self, infra):
        flags = self._get_infra_json('flags') or {}
        config_text = self._get_infra_text('config') or ''
        metrics_text = self._get_infra_text('metrics') or ''

        min_block = flags.get('storage.tsdb.min-block-duration', '')
        max_block = flags.get('storage.tsdb.max-block-duration', '')
        if min_block and max_block and min_block == max_block:
            infra['ha_setup'] = 'thanos-sidecar'
            infra['ha_signals'].append(f"min-block-duration == max-block-duration ({min_block})")

        if 'thanos_' in metrics_text or 'thanos' in config_text.lower():
            if not infra['ha_setup']:
                infra['ha_setup'] = 'thanos'
            infra['ha_signals'].append("Thanos metrics/config references detected")

        for t in self.findings['scrape_targets']:
            job = t.get('job', '').lower()
            if 'thanos' in job:
                if not infra['ha_setup']:
                    infra['ha_setup'] = 'thanos'
                infra['ha_signals'].append(f"Thanos scrape job: {t['job']}")
                break

        if 'cortex' in config_text.lower():
            infra['ha_setup'] = 'cortex'
            infra['ha_signals'].append("Cortex references in config")
        if 'mimir' in config_text.lower():
            infra['ha_setup'] = 'mimir'
            infra['ha_signals'].append("Mimir references in config")

        if 'remote_write' in config_text:
            for name in ['cortex', 'mimir', 'thanos']:
                if name in config_text.lower():
                    if not infra['ha_setup']:
                        infra['ha_setup'] = name
                    infra['ha_signals'].append(f"remote_write to {name} endpoint")

        if '/federate' in self.findings['accessible_endpoints']:
            if 'honor_labels' in config_text:
                if not infra['ha_setup']:
                    infra['ha_setup'] = 'federation'
                infra['ha_signals'].append("Federation endpoint accessible with honor_labels config")

    def run(self):
        print(BANNER)
        print(f"[+] Target: {self.base_url}")
        print(f"[+] Timeout: {self.timeout}s")
        print(f"[+] Go pprof: {'Available' if self.has_go_pprof else 'Not available'}")
        
        self.scan_status = "running"
        
        discovered = self.discover_endpoints()
        
        if not discovered and not self.findings['accessible_endpoints']:
            print("\n[!] No accessible endpoints discovered!")
            print("[!] Target may not be a Prometheus/Go service or is not accessible")
            print("[!] Skipping remaining scan phases")
            self.scan_status = "failed"
            self.update_status("failed", "No endpoints discovered - target not accessible", 100)
            self.scan_end = datetime.now()
            return
        
        all_endpoints = list(set(self._get_full_endpoints() + discovered))
        
        self.update_status("scanning", "Starting comprehensive scan...", 30)
        print("\n[*] PHASE 2: COMPREHENSIVE SCAN")
        print("="*80)
        
        pprof_profiles = []
        total_endpoints = len(all_endpoints)
        
        for idx, endpoint in enumerate(all_endpoints):
            progress = 30 + int((idx / total_endpoints) * 50)
            self.update_status("scanning", f"Scanning {endpoint}...", progress)
            
            success, content, content_type, headers = self.scan_endpoint(endpoint)
            
            if success:
                print(f"[+] {endpoint} ({len(content)} bytes)")
                self.findings['accessible_endpoints'].append(endpoint)
                
                if '/debug/pprof/' in endpoint and endpoint != '/debug/pprof/':
                    pprof_profiles.append(endpoint)
                
                self.check_dos_vectors(endpoint, headers)
                
                if '/config' in endpoint or '/status/config' in endpoint:
                    self.analyze_prometheus_config(content, endpoint)
                
                if '/targets' in endpoint:
                    self.analyze_targets(content, endpoint)
                
                print(f"[*] Running secret detection on {endpoint}...")
                self.analyze_content(content, endpoint)

                infra_endpoints = {'/api/v1/status/runtimeinfo', '/api/v1/status/buildinfo',
                                   '/api/v1/status/flags', '/api/v1/status/config',
                                   '/api/v1/targets', '/metrics'}
                ep_base = endpoint.split('?')[0]
                if endpoint in infra_endpoints or ep_base in {e.split('?')[0] for e in infra_endpoints}:
                    self._infra_raw[endpoint] = content

        self.update_status("scanning", "Analyzing infrastructure...", 79)
        print("\n[*] INFRASTRUCTURE ANALYSIS")
        print("="*80)
        self.analyze_infrastructure()

        if pprof_profiles:
            self.update_status("pprof", "Starting deep pprof analysis...", 80)
            print(f"\n[*] PHASE 3: DEEP PPROF ANALYSIS")
            print("="*80)
            print(f"[!] Analyzing {len(pprof_profiles)} pprof profiles for secrets...")
            
            total_profiles = len(pprof_profiles)
            for idx, profile_endpoint in enumerate(pprof_profiles):
                progress = 80 + int((idx / total_profiles) * 15)
                self.progress_percent = progress
                
                if '?' not in profile_endpoint:
                    self.analyze_pprof_profile(profile_endpoint, profile_endpoint.split('/')[-1])
        
        self.scan_end = datetime.now()
        self.scan_status = "complete"
        self.update_status("complete", "Scan complete", 100)
        
        print(f"\n[+] Scan complete in {(self.scan_end - self.scan_start).total_seconds():.2f}s")
        self.print_report()
    
    def print_report(self):
        print("\n" + "="*80)
        print("FIRETHIEF SCAN RESULTS")
        print("="*80)
        
        critical_creds = [c for c in self.findings['credentials'] if c.get('severity') == 'CRITICAL']
        
        if critical_creds:
            print("\n[CRITICAL] Credentials Exposed:")
            for cred in critical_creds[:10]:
                print(f"  {cred['type']}: {cred['value']}")
            if len(critical_creds) > 10:
                print(f"  ... and {len(critical_creds) - 10} more")
        
        print("\n" + "="*80)
        print("SUMMARY:")
        print(f"  Critical Findings: {len(critical_creds)}")
        print(f"  High Severity: {len([c for c in self.findings['credentials'] if c.get('severity') == 'HIGH']) + len(self.findings['secrets'])}")
        print(f"  DoS Vectors: {len(self.findings['dos_vectors'])}")
        print(f"  K8s Metadata: {len(self.findings['k8s'])}")
        print(f"  FQDNs: {len(set(f['value'] for f in self.findings['fqdns']))}")
        print("="*80)

        self._print_infra_summary()

    def _print_infra_summary(self):
        infra = self.findings['infrastructure']
        has_data = (infra['deployment_type'] or infra['prometheus_version'] or
                    infra['resource_limits'] or infra['ha_setup'] or infra['operator'])
        if not has_data:
            return

        print("\n" + "="*80)
        print("INFRASTRUCTURE ANALYSIS:")
        print("="*80)

        if infra['deployment_type']:
            sig_count = len(infra['deployment_signals'])
            print(f"\n  Deployment: {infra['deployment_type'].upper()} ({sig_count} signal{'s' if sig_count != 1 else ''})")
            for s in infra['deployment_signals']:
                print(f"    - {s}")

        if infra['prometheus_version']:
            go_ver = infra['node_info'].get('goVersion', '')
            goos = infra['node_info'].get('GOOS', '')
            goarch = infra['node_info'].get('GOARCH', '')
            parts = [f"v{infra['prometheus_version']}" if not infra['prometheus_version'].startswith('v') else infra['prometheus_version']]
            if go_ver:
                parts.append(f"Go {go_ver}")
            if goos and goarch:
                parts.append(f"{goos}/{goarch}")
            print(f"\n  Prometheus: {', '.join(parts)}")

        if infra['storage_retention']:
            print(f"  Storage Retention: {infra['storage_retention']}")

        if infra['resource_limits']:
            rl = infra['resource_limits']
            print("\n  Resources:")
            if 'cpu_cores' in rl:
                print(f"    CPU Cores (GOMAXPROCS): {rl['cpu_cores']}")
            if 'memory_human' in rl:
                print(f"    Memory (resident): {rl['memory_human']}")
            if 'goroutines' in rl:
                print(f"    Goroutines: {rl['goroutines']:,}")
            if 'open_fds' in rl:
                max_fds = rl.get('max_fds', '')
                fds_str = f"{rl['open_fds']:,}"
                if max_fds:
                    fds_str += f"/{max_fds:,}"
                print(f"    Open FDs: {fds_str}")
            if 'tsdb_head_series' in rl:
                print(f"    TSDB Head Series: {rl['tsdb_head_series']:,}")
            if 'go_alloc_human' in rl:
                print(f"    Go Heap Alloc: {rl['go_alloc_human']}")

        if infra['colocation']:
            jobs = ', '.join(c['job'] for c in infra['colocation'])
            print(f"\n  Co-located Services: {jobs}")

        if infra['operator']:
            print(f"\n  Operator: {infra['operator']}")
            for s in infra['operator_signals']:
                print(f"    - {s}")

        if infra['ha_setup']:
            print(f"\n  HA Setup: {infra['ha_setup']}")
            for s in infra['ha_signals']:
                print(f"    - {s}")

        print("="*80)

    def get_summary_stats(self) -> dict:
        return {
            'critical': len([c for c in self.findings['credentials'] if c.get('severity') == 'CRITICAL']),
            'high': len([c for c in self.findings['credentials'] if c.get('severity') == 'HIGH']) + len(self.findings['secrets']),
            'medium': len(self.findings['config_exposure']) + len(self.findings['k8s']),
            'low': len(set(f['value'] for f in self.findings['fqdns'])),
            'dos_vectors': len(self.findings['dos_vectors']),
            'accessible_endpoints': len(self.findings['accessible_endpoints']),
            'total_endpoints': len(self._get_full_endpoints()),
        }
    
    def get_status(self) -> dict:
        return {
            'status': self.scan_status,
            'phase': self.current_phase,
            'action': self.current_action,
            'progress': self.progress_percent,
            'start_time': self.scan_start.isoformat() if self.scan_start else None,
            'end_time': self.scan_end.isoformat() if self.scan_end else None,
            'target': self.base_url,
        }


def parse_target(target_str):
    """Parse a target URL in http://ip:port or https://ip:port format.
    Returns (scheme, host, port) or None on error."""
    target_str = target_str.strip()
    if not target_str:
        return None

    parsed = urlparse(target_str)
    if parsed.scheme not in ('http', 'https'):
        return None
    if not parsed.hostname:
        return None

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == 'https' else 80

    return (parsed.scheme, parsed.hostname, port)


def read_targets_file(filepath):
    """Read targets from a file, one http://ip:port per line.
    Returns list of (scheme, host, port) tuples."""
    targets = []
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parsed = parse_target(line)
                if parsed is None:
                    print(f"[!] Invalid target on line {line_num}: '{line}' "
                          f"(expected http://ip:port or https://ip:port)")
                    sys.exit(1)
                targets.append(parsed)
    except FileNotFoundError:
        print(f"[!] Targets file not found: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Permission denied reading: {filepath}")
        sys.exit(1)
    return targets


def main():
    parser = argparse.ArgumentParser(
        description='FireThief - Prometheus Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i 192.168.1.100 -p 9090 --web-ui
  %(prog)s -i prometheus.internal.com -p 9090 -v --save-profiles --web-ui
  %(prog)s -i 10.0.0.50 -p 9090 --web-ui --web-port 8080
  %(prog)s -T targets.txt
  %(prog)s -T targets.txt -v --save-profiles
        """
    )
    parser.add_argument('-i', '--ip', help='Target IP or hostname')
    parser.add_argument('-p', '--port', type=int, help='Target port')
    parser.add_argument('-T', '--targets', metavar='FILE',
                        help='File containing targets, one per line in http://ip:port format')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout (default: 10s)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--save-profiles', action='store_true', help='Save downloaded pprof profiles')
    parser.add_argument('-o', '--output', help='Output directory for saved profiles')
    parser.add_argument('--web-ui', action='store_true', help='Launch web UI')
    parser.add_argument('--web-port', type=int, default=5000, help='Web UI port (default: 5000)')

    args = parser.parse_args()

    targets = []

    if args.targets:
        targets.extend(read_targets_file(args.targets))

    if args.ip and args.port:
        targets.append(('http', args.ip, args.port))
    elif args.ip or args.port:
        if not args.targets:
            print("[!] Both -i/--ip and -p/--port are required when not using -T/--targets")
            sys.exit(1)

    if not targets:
        print("[!] No targets specified. Use -i/-p or -T to specify targets.")
        parser.print_help()
        sys.exit(1)

    if args.web_ui:
        scanners = []
        for scheme, host, port in targets:
            scanners.append(PrometheusScanner(host, port, args.timeout, args.verbose, args.save_profiles, args.output, scheme=scheme))

        create_web_ui(scanners, args.web_port)
        time.sleep(1)

        def run_all_scans():
            for scanner in scanners:
                scanner.run()

        scan_thread = threading.Thread(target=run_all_scans, daemon=False)
        scan_thread.start()

        print(f"\n[*] Scanning {len(scanners)} target(s)... Press Ctrl+C to exit")
        try:
            scan_thread.join()
            print("\n[*] All scans complete. Web UI still available. Press Ctrl+C to exit...")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[+] Shutting down...")
    else:
        for idx, (scheme, host, port) in enumerate(targets):
            if len(targets) > 1:
                print(f"\n{'#'*80}")
                print(f"# TARGET {idx + 1}/{len(targets)}: {scheme}://{host}:{port}")
                print(f"{'#'*80}")

            scanner = PrometheusScanner(host, port, args.timeout, args.verbose, args.save_profiles, args.output, scheme=scheme)
            scanner.run()

    return 0


if __name__ == '__main__':
    sys.exit(main())
