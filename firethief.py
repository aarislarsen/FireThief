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
from flask import Flask, render_template_string, send_from_directory, jsonify
from flask_cors import CORS
import threading
import webbrowser
import time

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
                 save_profiles: bool = False, output_dir: str = None):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
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
            'accessible_endpoints': []
        }
        
        self.endpoints = self._get_discovery_endpoints()
        self.patterns = self._compile_patterns()
        
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
            
            resp = requests.get(url, timeout=30, verify=False, allow_redirects=True)
            
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
    
    def _compile_patterns(self) -> dict:
        return {
            'secret_keywords': re.compile(
                r'(?i)(password|passwd|pwd|secret|token|apikey|api_key|auth|bearer|jwt|'
                r'authorization|client_secret|refresh_token|access_token|private_key|'
                r'secret_access_key|api_secret|service_account|ssh_key|ssl_key|tls_key|'
                r'encryption_key|master_key|session_key|cookie_secret|webhook_secret|'
                r'signing_secret|slack_token|github_token|gitlab_token|datadog_api_key|'
                r'newrelic_api_key|sendgrid_api_key|twilio_auth_token|stripe_key|'
                r'paypal_secret|square_token|shopify_api_key)[\s:="\'\[]+([^\s"\'}\],]{8,})',
                re.IGNORECASE
            ),
            'aws_key': re.compile(r'(AKIA[0-9A-Z]{16})'),
            'aws_secret': re.compile(r'(?i)(aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[\s:="\'\[]+([A-Za-z0-9/+=]{40})'),
            'aws_session': re.compile(r'(?i)(aws_session_token|AWS_SESSION_TOKEN)[\s:="\'\[]+([A-Za-z0-9/+=]{100,})'),
            'azure_client_secret': re.compile(r'(?i)(azure_client_secret|AZURE_CLIENT_SECRET)[\s:="\'\[]+([A-Za-z0-9~._-]{32,})'),
            'azure_storage': re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+'),
            'gcp_api_key': re.compile(r'AIza[0-9A-Za-z_\-]{35}'),
            'github_pat': re.compile(r'ghp_[A-Za-z0-9]{36}'),
            'github_oauth': re.compile(r'gho_[A-Za-z0-9]{36}'),
            'github_app': re.compile(r'ghs_[A-Za-z0-9]{36}'),
            'github_refresh': re.compile(r'ghr_[A-Za-z0-9]{36}'),
            'github_fine_grained': re.compile(r'github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}'),
            'gitlab_pat': re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'),
            'gitlab_runner': re.compile(r'glrt-[A-Za-z0-9\-_]{20,}'),
            'npm_token': re.compile(r'npm_[A-Za-z0-9]{36}'),
            'pypi_token': re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}'),
            'slack_bot_token': re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}'),
            'slack_user_token': re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}'),
            'slack_workspace': re.compile(r'xoxa-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}'),
            'slack_webhook': re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}'),
            'heroku_api': re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
            'mailgun_api': re.compile(r'key-[0-9a-zA-Z]{32}'),
            'mailgun_signing': re.compile(r'pubkey-[0-9a-f]{32}'),
            'stripe_live_secret': re.compile(r'sk_live_[A-Za-z0-9]{24,}'),
            'stripe_test_secret': re.compile(r'sk_test_[A-Za-z0-9]{24,}'),
            'stripe_live_pub': re.compile(r'pk_live_[A-Za-z0-9]{24,}'),
            'stripe_restricted': re.compile(r'rk_live_[A-Za-z0-9]{24,}'),
            'square_access': re.compile(r'sq0atp-[A-Za-z0-9\-_]{22}'),
            'square_oauth': re.compile(r'sq0csp-[A-Za-z0-9\-_]{43}'),
            'twilio_account_sid': re.compile(r'AC[0-9a-f]{32}'),
            'twilio_api_key': re.compile(r'SK[0-9a-f]{32}'),
            'sendgrid_api': re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
            'digitalocean_pat': re.compile(r'dop_v1_[a-f0-9]{64}'),
            'digitalocean_oauth': re.compile(r'doo_v1_[a-f0-9]{64}'),
            'digitalocean_refresh': re.compile(r'dor_v1_[a-f0-9]{64}'),
            'shopify_token': re.compile(r'shpat_[a-fA-F0-9]{32}'),
            'shopify_shared': re.compile(r'shpss_[a-fA-F0-9]{32}'),
            'shopify_custom': re.compile(r'shpca_[a-fA-F0-9]{32}'),
            'shopify_private': re.compile(r'shppa_[a-fA-F0-9]{32}'),
            'atlassian_api': re.compile(r'(?i)atlassian[_-]?api[_-]?token[\s:="\'\[]+([A-Za-z0-9]{24})'),
            'datadog_api': re.compile(r'[a-f0-9]{32}(?=.*datadog)', re.IGNORECASE),
            'datadog_app': re.compile(r'[a-f0-9]{40}(?=.*datadog)', re.IGNORECASE),
            'newrelic_api': re.compile(r'NRAK-[A-Z0-9]{27}'),
            'newrelic_insights': re.compile(r'NRIQ-[A-Z0-9]{32}'),
            'pagerduty_api': re.compile(r'[a-z0-9+_\-]{20}'),
            'grafana_key': re.compile(r'glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}'),
            'grafana_service_account': re.compile(r'glc_[A-Za-z0-9+/]{32,}={0,2}'),
            'ssh_private_key': re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
            'ssh_private_key_full': re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]{100,}-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
            'pgp_private_key': re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
            'generic_api_key': re.compile(r'(?i)api[_-]?key[\s:="\'\[]+([A-Za-z0-9+/]{32,}={0,2})'),
            'db_uri': re.compile(
                r'(postgres|postgresql|mysql|mariadb|mongodb|mongo|redis|memcached|amqp|rabbitmq|kafka|'
                r'elasticsearch|cassandra|couchdb|neo4j|influxdb|timescaledb|clickhouse)://[^\s"\'<>\]]+',
                re.IGNORECASE
            ),
            'jdbc_url': re.compile(r'jdbc:[a-z]+://[^\s"\'<>\]]+', re.IGNORECASE),
            'jdbc_with_creds': re.compile(r'jdbc:[a-z]+://[^:]+:[^@]+@[^\s"\'<>\]]+', re.IGNORECASE),
            'odbc_connection': re.compile(r'Driver={[^}]+};.*(?:PWD|Password)=[^;]+', re.IGNORECASE),
            'odbc_dsn': re.compile(r'DSN=[^;]+;.*(?:PWD|Password)=[^;]+', re.IGNORECASE),
            'sqlalchemy_url': re.compile(r'(?:postgresql|mysql|sqlite|oracle|mssql)\+[a-z]+://[^\s"\'<>\]]+', re.IGNORECASE),
            'connection_string': re.compile(
                r'(?i)(database|db|connection|conn)[\s:="\'\[]+[^:]+://[^:]+:[^@]+@[^\s"\'<>\]]+',
                re.IGNORECASE
            ),
            'mongodb_srv': re.compile(r'mongodb\+srv://[^\s"\'<>\]]+', re.IGNORECASE),
            'mongodb_atlas': re.compile(r'mongodb://[^:]+:[^@]+@[^/]+\.mongodb\.net[^\s"\'<>\]]*', re.IGNORECASE),
            'jwt': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
            'basic_auth_url': re.compile(r'https?://[^:/@\s]+:[^@/\s]+@[^\s"\'<>\]]+'),
            'bearer_token': re.compile(r'[Bb]earer\s+([A-Za-z0-9\-._~+/]+=*)'),
            'api_token_header': re.compile(r'(?i)(x-api-key|api-key|apikey)[\s:="\'\[]+([A-Za-z0-9\-_]{20,})'),
            'fqdn': re.compile(
                r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+' +
                r'(?:' +
                r'local|internal|corp|private|lan|home|' +
                r'svc\.cluster\.local|cluster\.local|' +
                r'company\.(?:com|net|org|io|dev|co\.uk)|' +
                r'staging|stage|dev|prod|production|test|qa|uat|' +
                r'k8s|kubernetes|kube|rancher|openshift|' +
                r'internal\.aws|ec2\.internal|compute\.internal|' +
                r'internal\.azure|internal\.gcp|' +
                r'amazonaws\.com|cloudapp\.net|googleapis\.com|' +
                r'com|net|org|edu|gov|mil|int|' +
                r'io|co|ai|app|dev|cloud|tech|online|site|' +
                r'de|uk|fr|jp|cn|au|ca|br|ru|in|it|nl|es|se|no|dk|fi|' +
                r'info|biz|name|pro' +
                r')\b',
                re.IGNORECASE
            ),
            'internal_url': re.compile(
                r'https?://(?:internal|api-internal|admin|staging|stage|dev|test|qa|'
                r'backend|private|vault|consul|etcd|grafana|kibana|jenkins|'
                r'localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
                r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
                r'192\.168\.\d{1,3}\.\d{1,3})[^\s"\'<>\]]*',
                re.IGNORECASE
            ),
            'k8s_service_url': re.compile(
                r'https?://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.svc(?:\.cluster\.local)?(?::\d+)?[^\s"\'<>\]]*'
            ),
            'registry': re.compile(
                r'(?:registry|gcr\.io|ghcr\.io|quay\.io|index\.docker\.io|docker\.io|'
                r'[a-z0-9-]+\.azurecr\.io|'
                r'[0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com|'
                r'[a-z0-9-]+\.pkg\.dev|'
                r'harbor\.[^\s"\'<>\]]+|'
                r'nexus\.[^\s"\'<>\]]+|'
                r'artifactory\.[^\s"\'<>\]]+)[^\s"\'<>\]]*',
                re.IGNORECASE
            ),
            'docker_image': re.compile(r'(?:[a-z0-9.-]+/)?[a-z0-9._-]+:[a-z0-9._-]+'),
            'k8s_namespace': re.compile(r'(?:namespace|kube_namespace)[\s:="\'\[]+([a-z0-9-]+)'),
            'k8s_pod_name': re.compile(r'(?:pod|kube_pod_name|pod_name)[\s:="\'\[]+([a-z0-9-]+)'),
            'k8s_service': re.compile(r'(?:service|kube_service)[\s:="\'\[]+([a-z0-9-]+)'),
            'k8s_ingress': re.compile(r'(?:kube_ingress_path|ingress_path)[\s:="\'\[]+([^\s"\'}\]]+)'),
            'k8s_ingress_host': re.compile(r'(?:kube_ingress_host|ingress_host)[\s:="\'\[]+([^\s"\'}\]]+)'),
            'k8s_deployment': re.compile(r'(?:deployment|kube_deployment)[\s:="\'\[]+([a-z0-9-]+)'),
            'k8s_secret_ref': re.compile(r'(?:secret|secretName|secret_name)[\s:="\'\[]+([a-z0-9-]+)'),
            'k8s_configmap': re.compile(r'(?:configmap|configMapName)[\s:="\'\[]+([a-z0-9-]+)'),
            'k8s_node': re.compile(r'(?:node|kube_node|node_name)[\s:="\'\[]+([a-z0-9.-]+)'),
            'k8s_sa_token': re.compile(r'(?:serviceaccount|service_account).*?token[\s:="\'\[]+([A-Za-z0-9\-._]{20,})'),
            'secret_paths': re.compile(
                r'/(?:var/lib/k8s/secrets|etc/kubernetes/pki|root/\.ssh|home/[^/]+/\.ssh|'
                r'etc/ssl|opt/secrets|etc/pki|var/secrets|run/secrets|'
                r'\.aws/credentials|\.kube/config|\.docker/config\.json|'
                r'etc/rancher|var/lib/rancher)[^\s"\'<>\]]*'
            ),
            'cert_files': re.compile(r'[^\s"\'<>\]]*\.(?:pem|key|crt|cer|p12|pfx|jks|keystore)'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'private_ip': re.compile(
                r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
                r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
                r'192\.168\.\d{1,3}\.\d{1,3})\b'
            ),
            'route_handler': re.compile(r'(?:Handler|handleFunc|ServeHTTP|http\.).*?([/][a-z0-9/_\-{}]+)'),
            'http_route': re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+([/][a-z0-9/_\-{}:]+)'),
            'webhook': re.compile(
                r'https?://(?:hooks\.slack\.com|discord\.com/api/webhooks|'
                r'outlook\.office\.com/webhook|api\.telegram\.org/bot)[^\s"\'<>\]]+',
                re.IGNORECASE
            ),
            'discord_webhook': re.compile(r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
            'env_var_secret': re.compile(r'(?:export\s+)?([A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL))=([^\s]+)'),
        }
    
    def scan_endpoint(self, endpoint: str) -> Tuple[bool, bytes, str, dict]:
        url = urljoin(self.base_url, endpoint)
        try:
            if self.verbose:
                print(f"[*] Scanning: {url}")
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
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
            self.findings['secrets'].append({
                'type': 'keyword_secret',
                'keyword': match.group(1),
                'value': match.group(2)[:50] + ('...' if len(match.group(2)) > 50 else ''),
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['aws_key'].finditer(text):
            self.findings['credentials'].append({
                'type': 'AWS_ACCESS_KEY_ID',
                'value': match.group(1),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['aws_secret'].finditer(text):
            self.findings['credentials'].append({
                'type': 'AWS_SECRET_ACCESS_KEY',
                'value': match.group(2)[:20] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['aws_session'].finditer(text):
            self.findings['credentials'].append({
                'type': 'AWS_SESSION_TOKEN',
                'value': match.group(2)[:30] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['azure_client_secret'].finditer(text):
            self.findings['credentials'].append({
                'type': 'AZURE_CLIENT_SECRET',
                'value': match.group(2)[:20] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['azure_storage'].finditer(text):
            self.findings['credentials'].append({
                'type': 'AZURE_STORAGE_CONNECTION_STRING',
                'value': match.group(0)[:50] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['gcp_api_key'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GCP_API_KEY',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['github_pat'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GITHUB_PERSONAL_ACCESS_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['github_oauth'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GITHUB_OAUTH_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['github_app'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GITHUB_APP_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['github_fine_grained'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GITHUB_FINE_GRAINED_PAT',
                'value': match.group(0)[:50] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['gitlab_pat'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GITLAB_PERSONAL_ACCESS_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['gitlab_runner'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GITLAB_RUNNER_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['npm_token'].finditer(text):
            self.findings['credentials'].append({
                'type': 'NPM_ACCESS_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['pypi_token'].finditer(text):
            self.findings['credentials'].append({
                'type': 'PYPI_API_TOKEN',
                'value': match.group(0)[:50] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['slack_bot_token'].finditer(text):
            self.findings['credentials'].append({
                'type': 'SLACK_BOT_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['slack_user_token'].finditer(text):
            self.findings['credentials'].append({
                'type': 'SLACK_USER_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['slack_webhook'].finditer(text):
            self.findings['credentials'].append({
                'type': 'SLACK_WEBHOOK_URL',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['stripe_live_secret'].finditer(text):
            self.findings['credentials'].append({
                'type': 'STRIPE_LIVE_SECRET_KEY',
                'value': match.group(0)[:30] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['stripe_live_pub'].finditer(text):
            self.findings['credentials'].append({
                'type': 'STRIPE_LIVE_PUBLISHABLE_KEY',
                'value': match.group(0)[:30] + '...',
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['square_access'].finditer(text):
            self.findings['credentials'].append({
                'type': 'SQUARE_ACCESS_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['twilio_account_sid'].finditer(text):
            self.findings['credentials'].append({
                'type': 'TWILIO_ACCOUNT_SID',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['twilio_api_key'].finditer(text):
            self.findings['credentials'].append({
                'type': 'TWILIO_API_KEY',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['sendgrid_api'].finditer(text):
            self.findings['credentials'].append({
                'type': 'SENDGRID_API_KEY',
                'value': match.group(0)[:30] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['digitalocean_pat'].finditer(text):
            self.findings['credentials'].append({
                'type': 'DIGITALOCEAN_PERSONAL_ACCESS_TOKEN',
                'value': match.group(0)[:30] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['shopify_token'].finditer(text):
            self.findings['credentials'].append({
                'type': 'SHOPIFY_ACCESS_TOKEN',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['ssh_private_key_full'].finditer(text):
            self.findings['credentials'].append({
                'type': 'SSH_PRIVATE_KEY',
                'value': 'FULL PRIVATE KEY DETECTED',
                'endpoint': endpoint,
                'severity': 'CRITICAL',
                'note': 'Complete SSH private key found in content'
            })
        
        for match in self.patterns['ssh_private_key'].finditer(text):
            if not any(c.get('type') == 'SSH_PRIVATE_KEY' and c.get('endpoint') == endpoint 
                      for c in self.findings['credentials']):
                self.findings['credentials'].append({
                    'type': 'SSH_PRIVATE_KEY_HEADER',
                    'value': 'SSH PRIVATE KEY DETECTED',
                    'endpoint': endpoint,
                    'severity': 'CRITICAL'
                })
        
        for match in self.patterns['db_uri'].finditer(text):
            self.findings['credentials'].append({
                'type': 'DATABASE_URI',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['jdbc_with_creds'].finditer(text):
            self.findings['credentials'].append({
                'type': 'JDBC_URL_WITH_CREDENTIALS',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['odbc_connection'].finditer(text):
            self.findings['credentials'].append({
                'type': 'ODBC_CONNECTION_STRING',
                'value': match.group(0)[:100] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['mongodb_atlas'].finditer(text):
            self.findings['credentials'].append({
                'type': 'MONGODB_ATLAS_CONNECTION',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['connection_string'].finditer(text):
            self.findings['credentials'].append({
                'type': 'CONNECTION_STRING_WITH_CREDENTIALS',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['jwt'].finditer(text):
            self.findings['credentials'].append({
                'type': 'JWT_TOKEN',
                'value': match.group(0)[:100] + '...',
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['bearer_token'].finditer(text):
            self.findings['credentials'].append({
                'type': 'BEARER_TOKEN',
                'value': match.group(1)[:50] + '...',
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['api_token_header'].finditer(text):
            self.findings['credentials'].append({
                'type': 'API_TOKEN_HEADER',
                'header': match.group(1),
                'value': match.group(2)[:30] + '...',
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['basic_auth_url'].finditer(text):
            self.findings['credentials'].append({
                'type': 'BASIC_AUTH_URL',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'CRITICAL'
            })
        
        for match in self.patterns['webhook'].finditer(text):
            self.findings['credentials'].append({
                'type': 'WEBHOOK_URL',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'MEDIUM'
            })
        
        for match in self.patterns['discord_webhook'].finditer(text):
            self.findings['credentials'].append({
                'type': 'DISCORD_WEBHOOK_URL',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'MEDIUM'
            })
        
        for match in self.patterns['grafana_key'].finditer(text):
            self.findings['credentials'].append({
                'type': 'GRAFANA_API_KEY',
                'value': match.group(0),
                'endpoint': endpoint,
                'severity': 'HIGH'
            })
        
        for match in self.patterns['k8s_sa_token'].finditer(text):
            self.findings['credentials'].append({
                'type': 'K8S_SERVICE_ACCOUNT_TOKEN',
                'value': match.group(1)[:30] + '...',
                'endpoint': endpoint,
                'severity': 'CRITICAL',
                'note': 'K8s SA token - can be used for cluster access'
            })
        
        for match in self.patterns['env_var_secret'].finditer(text):
            self.findings['credentials'].append({
                'type': 'ENVIRONMENT_VARIABLE_SECRET',
                'variable': match.group(1),
                'value': match.group(2)[:50] + '...',
                'endpoint': endpoint,
                'severity': 'HIGH'
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
        }


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FireThief - {{ target }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1d3a 100%);
            color: #e0e0e0;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: linear-gradient(135deg, #1e2749 0%, #2d3561 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.5);
            border: 1px solid #3a4466;
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            color: #ff6b6b;
            font-size: 2.5em;
            text-shadow: 0 0 10px rgba(255, 107, 107, 0.5);
            letter-spacing: 2px;
        }

        .subtitle {
            color: #a8b2d1;
            font-size: 0.9em;
            margin-top: 5px;
        }

        .target-info {
            background: rgba(255, 107, 107, 0.1);
            padding: 15px 25px;
            border-radius: 5px;
            border-left: 4px solid #ff6b6b;
        }

        .target-info h2 {
            color: #ff6b6b;
            font-size: 1.2em;
            margin-bottom: 5px;
        }

        .target-info p {
            color: #a8b2d1;
            font-size: 0.9em;
        }

        .progress-section {
            background: linear-gradient(135deg, #1e2749 0%, #252d4f 100%);
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 1px solid #3a4466;
        }

        .progress-bar {
            width: 100%;
            height: 30px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 15px;
            overflow: hidden;
            margin-bottom: 15px;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #ff6b6b 0%, #ff9f43 100%);
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }

        .progress-text {
            color: #a8b2d1;
            font-size: 0.9em;
        }

        .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            margin-top: 10px;
        }

        .status-running { background: #ff9f43; color: #000; }
        .status-complete { background: #48dbfb; color: #000; }
        .status-failed { background: #ff6b6b; color: #fff; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(135deg, #1e2749 0%, #252d4f 100%);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid #3a4466;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
        }

        .stat-card.critical { border-left: 4px solid #ff6b6b; }
        .stat-card.high { border-left: 4px solid #ff9f43; }
        .stat-card.medium { border-left: 4px solid #feca57; }
        .stat-card.low { border-left: 4px solid #48dbfb; }

        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .stat-card.critical .stat-number { color: #ff6b6b; }
        .stat-card.high .stat-number { color: #ff9f43; }
        .stat-card.medium .stat-number { color: #feca57; }
        .stat-card.low .stat-number { color: #48dbfb; }

        .stat-label {
            color: #a8b2d1;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }

        .findings-section {
            background: linear-gradient(135deg, #1e2749 0%, #252d4f 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid #3a4466;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #3a4466;
        }

        .section-title {
            font-size: 1.5em;
            color: #e0e0e0;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.7em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .severity-critical { background: #ff6b6b; color: #fff; }
        .severity-high { background: #ff9f43; color: #fff; }
        .severity-medium { background: #feca57; color: #000; }
        .severity-low { background: #48dbfb; color: #000; }

        .finding-item {
            background: rgba(255, 255, 255, 0.03);
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #48dbfb;
            transition: background 0.3s ease;
        }

        .finding-item:hover {
            background: rgba(255, 255, 255, 0.08);
        }

        .finding-item.critical { border-left-color: #ff6b6b; }
        .finding-item.high { border-left-color: #ff9f43; }
        .finding-item.medium { border-left-color: #feca57; }

        .finding-type {
            color: #64ffda;
            font-weight: bold;
            margin-bottom: 8px;
            font-size: 1.1em;
        }

        .finding-value {
            background: rgba(0, 0, 0, 0.3);
            padding: 10px 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            color: #ff6b6b;
            margin: 10px 0;
            word-break: break-all;
            border: 1px solid rgba(255, 107, 107, 0.3);
            white-space: pre-wrap;
        }

        .finding-endpoint {
            color: #a8b2d1;
            font-size: 0.85em;
            margin-top: 8px;
        }

        .finding-note {
            color: #feca57;
            font-style: italic;
            margin-top: 5px;
            font-size: 0.9em;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #48dbfb;
        }

        .empty-state-icon {
            font-size: 3em;
            margin-bottom: 15px;
        }

        footer {
            text-align: center;
            padding: 30px;
            margin-top: 40px;
            color: #a8b2d1;
            border-top: 1px solid #3a4466;
        }

        .footer-links {
            margin-top: 15px;
        }

        .footer-links a {
            color: #64ffda;
            text-decoration: none;
            margin: 0 10px;
            transition: color 0.3s ease;
        }

        .footer-links a:hover {
            color: #ff6b6b;
        }

        .collapsible {
            cursor: pointer;
            user-select: none;
        }

        .collapsible::before {
            content: '▼ ';
            display: inline-block;
            transition: transform 0.3s ease;
        }

        .collapsible.collapsed::before {
            transform: rotate(-90deg);
        }

        .collapsible-content {
            max-height: 5000px;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }

        .collapsible-content.hidden {
            max-height: 0;
        }

        .domain-list {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .domain-item {
            background: rgba(0, 0, 0, 0.2);
            padding: 8px 12px;
            border-radius: 4px;
            border-left: 2px solid #48dbfb;
        }

        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 20px;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            h1 {
                font-size: 1.8em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-content">
                <div>
                    <h1>🔥 FIRETHIEF</h1>
                    <p class="subtitle">Prometheus Security Assessment Framework</p>
                </div>
                <div class="target-info">
                    <h2>Target</h2>
                    <p>{{ target }}</p>
                    <p style="font-size: 0.8em; margin-top: 5px;">Started: <span id="scan-time">{{ scan_time }}</span></p>
                </div>
            </div>
        </header>

        <div class="progress-section">
            <div class="progress-bar">
                <div class="progress-fill" id="progress-bar" style="width: 0%;">
                    <span id="progress-percent">0%</span>
                </div>
            </div>
            <div class="progress-text" id="progress-text">Initializing scan...</div>
            <span class="status-badge status-running" id="status-badge">RUNNING</span>
        </div>

        <div class="stats-grid" id="stats-grid">
            <div class="stat-card critical">
                <div class="stat-number" id="stat-critical">0</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number" id="stat-high">0</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number" id="stat-medium">0</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number" id="stat-low">0</div>
                <div class="stat-label">Low / Info</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #ff6b6b;" id="stat-dos">0</div>
                <div class="stat-label">DoS Vectors</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #64ffda;" id="stat-endpoints">0</div>
                <div class="stat-label">Accessible Endpoints</div>
            </div>
        </div>

        <div id="findings-container"></div>

        <footer>
            <p>FireThief v1.0 - Prometheus Security Scanner</p>
            <p style="font-size: 0.85em; margin-top: 10px;">"Stealing fire from the Titans"</p>
            <div class="footer-links">
                <a href="https://www.aquasec.com/blog/300000-prometheus-servers-and-exporters-exposed-to-dos-attacks/" target="_blank">Aqua Research</a>
                <a href="https://www.sysdig.com/blog/exposed-prometheus-exploit-kubernetes-kubeconeu" target="_blank">Sysdig K8s</a>
                <a href="https://redsentry.com/resources/blog/securing-go-applications-against-debug-pprof-exploits" target="_blank">Red Sentry</a>
            </div>
        </footer>
    </div>

    <script>
        let lastUpdate = null;

        function updateUI() {
            fetch('/api/data')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('stat-critical').textContent = data.stats.critical;
                    document.getElementById('stat-high').textContent = data.stats.high;
                    document.getElementById('stat-medium').textContent = data.stats.medium;
                    document.getElementById('stat-low').textContent = data.stats.low;
                    document.getElementById('stat-dos').textContent = data.stats.dos_vectors;
                    document.getElementById('stat-endpoints').textContent = data.stats.accessible_endpoints;

                    const progress = data.status.progress;
                    document.getElementById('progress-bar').style.width = progress + '%';
                    document.getElementById('progress-percent').textContent = progress + '%';
                    document.getElementById('progress-text').textContent = data.status.action || 'Processing...';

                    const statusBadge = document.getElementById('status-badge');
                    statusBadge.className = 'status-badge status-' + data.status.status;
                    statusBadge.textContent = data.status.status.toUpperCase();

                    if (JSON.stringify(data.findings) !== lastUpdate) {
                        renderFindings(data.findings);
                        lastUpdate = JSON.stringify(data.findings);
                    }

                    if (data.status.status === 'running') {
                        setTimeout(updateUI, 1000);
                    } else {
                        if (data.status.end_time) {
                            const endTime = new Date(data.status.end_time);
                            document.getElementById('scan-time').textContent = 
                                'Completed: ' + endTime.toLocaleString();
                        }
                    }
                })
                .catch(error => {
                    console.error('Error updating UI:', error);
                    setTimeout(updateUI, 2000);
                });
        }

        function renderFindings(findings) {
            const container = document.getElementById('findings-container');
            container.innerHTML = `
                ${renderCriticalFindings(findings.critical_findings)}
                ${renderHighFindings(findings.high_findings)}
                ${renderDosVectors(findings.dos_vectors)}
                ${renderConfigExposure(findings.config_exposure)}
                ${renderK8sFindings(findings.k8s_findings)}
                ${renderContainers(findings.containers)}
                ${renderInternalRoutes(findings.internal_routes)}
                ${renderFqdns(findings.fqdns)}
                ${renderScrapeTargets(findings.scrape_targets)}
            `;
        }

        function renderCriticalFindings(findings) {
            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible" onclick="toggleSection(this)">
                            🚨 Critical Findings
                        </h2>
                        <span class="severity-badge severity-critical">CRITICAL</span>
                    </div>
                    <div class="collapsible-content">
                        ${findings && findings.length > 0 ? findings.map(f => `
                            <div class="finding-item critical">
                                <div class="finding-type">${f.type}</div>
                                <div class="finding-value">${f.value}</div>
                                <div class="finding-endpoint">📍 Endpoint: ${f.endpoint}</div>
                                ${f.note ? `<div class="finding-note">⚠️ ${f.note}</div>` : ''}
                            </div>
                        `).join('') : `
                            <div class="empty-state">
                                <div class="empty-state-icon">✓</div>
                                <p>No critical credential exposures detected</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }

        function renderHighFindings(findings) {
            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible" onclick="toggleSection(this)">
                            🔐 Secrets & Tokens
                        </h2>
                        <span class="severity-badge severity-high">HIGH</span>
                    </div>
                    <div class="collapsible-content">
                        ${findings && findings.length > 0 ? findings.map(f => `
                            <div class="finding-item high">
                                <div class="finding-type">${f.type}</div>
                                ${f.keyword ? `<div style="color: #a8b2d1; font-size: 0.9em; margin: 5px 0;">Keyword: ${f.keyword}</div>` : ''}
                                <div class="finding-value">${f.value}</div>
                                <div class="finding-endpoint">📍 Endpoint: ${f.endpoint}</div>
                            </div>
                        `).join('') : `
                            <div class="empty-state">
                                <div class="empty-state-icon">✓</div>
                                <p>No secret patterns detected</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }

        function renderDosVectors(findings) {
            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible" onclick="toggleSection(this)">
                            💥 DoS Attack Vectors
                        </h2>
                        <span class="severity-badge severity-high">HIGH</span>
                    </div>
                    <div class="collapsible-content">
                        ${findings && findings.length > 0 ? findings.map(f => `
                            <div class="finding-item high">
                                <div class="finding-type">${f.issue}</div>
                                <div class="finding-endpoint">📍 Endpoint: ${f.endpoint}</div>
                                <div class="finding-note">📚 Reference: ${f.reference}</div>
                            </div>
                        `).join('') : `
                            <div class="empty-state">
                                <div class="empty-state-icon">✓</div>
                                <p>No DoS vectors detected</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }

        function renderConfigExposure(findings) {
            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible" onclick="toggleSection(this)">
                            ⚙️ Configuration Exposure
                        </h2>
                        <span class="severity-badge severity-medium">MEDIUM</span>
                    </div>
                    <div class="collapsible-content">
                        ${findings && findings.length > 0 ? findings.map(f => `
                            <div class="finding-item medium">
                                <div class="finding-type">${f.type}</div>
                                <div class="finding-note">${f.issue}</div>
                                <div class="finding-endpoint">📍 Endpoint: ${f.endpoint}</div>
                            </div>
                        `).join('') : `
                            <div class="empty-state">
                                <div class="empty-state-icon">✓</div>
                                <p>No configuration exposure detected</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }

        function renderK8sFindings(findings) {
            let content = '';
            if (findings && Object.keys(findings).length > 0) {
                for (const [type, items] of Object.entries(findings)) {
                    content += `
                        <div class="finding-item medium">
                            <div class="finding-type">${type}</div>
                            <div class="finding-value">${items.join(', ')}</div>
                        </div>
                    `;
                }
            } else {
                content = `
                    <div class="empty-state">
                        <div class="empty-state-icon">✓</div>
                        <p>No Kubernetes metadata exposed</p>
                    </div>
                `;
            }

            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible" onclick="toggleSection(this)">
                            ☸️ Kubernetes Metadata
                        </h2>
                        <span class="severity-badge severity-medium">MEDIUM</span>
                    </div>
                    <div class="collapsible-content">
                        ${content}
                    </div>
                </div>
            `;
        }

        function renderContainers(containers) {
            let content = '';
            if (containers && (containers.registries.length > 0 || containers.images.length > 0)) {
                if (containers.registries.length > 0) {
                    content += `
                        <div class="finding-item">
                            <div class="finding-type">Container Registries (${containers.registries.length})</div>
                            <div class="domain-list">
                                ${containers.registries.map(r => `<div class="domain-item">${r}</div>`).join('')}
                            </div>
                        </div>
                    `;
                }
                if (containers.images.length > 0) {
                    const displayImages = containers.images.slice(0, 20);
                    content += `
                        <div class="finding-item">
                            <div class="finding-type">Container Images (${containers.images.length})</div>
                            <div class="domain-list">
                                ${displayImages.map(i => `<div class="domain-item">${i}</div>`).join('')}
                                ${containers.images.length > 20 ? `<div style="color: #a8b2d1; padding: 8px 12px;">... and ${containers.images.length - 20} more</div>` : ''}
                            </div>
                        </div>
                    `;
                }
            } else {
                content = `
                    <div class="empty-state">
                        <div class="empty-state-icon">✓</div>
                        <p>No container infrastructure information found</p>
                    </div>
                `;
            }

            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible collapsed" onclick="toggleSection(this)">
                            🐳 Container Infrastructure
                        </h2>
                        <span class="severity-badge severity-low">INFO</span>
                    </div>
                    <div class="collapsible-content hidden">
                        ${content}
                    </div>
                </div>
            `;
        }

        function renderInternalRoutes(routes) {
            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible collapsed" onclick="toggleSection(this)">
                            🛣️ Internal Routes
                        </h2>
                        <span class="severity-badge severity-low">INFO</span>
                    </div>
                    <div class="collapsible-content hidden">
                        ${routes && routes.length > 0 ? `
                            <div class="finding-item">
                                <div class="finding-type">Discovered Routes (${routes.length})</div>
                                <div class="domain-list">
                                    ${routes.map(r => `<div class="domain-item">${r}</div>`).join('')}
                                </div>
                            </div>
                        ` : `
                            <div class="empty-state">
                                <div class="empty-state-icon">✓</div>
                                <p>No internal routes discovered</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }

        function renderFqdns(fqdns) {
            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible collapsed" onclick="toggleSection(this)">
                            🌐 FQDNs & Network Topology
                        </h2>
                        <span class="severity-badge severity-low">INFO</span>
                    </div>
                    <div class="collapsible-content hidden">
                        ${fqdns && fqdns.length > 0 ? `
                            <div class="finding-item">
                                <div class="finding-type">Discovered Domains (${fqdns.length})</div>
                                <div class="domain-list">
                                    ${fqdns.map(f => `<div class="domain-item">${f}</div>`).join('')}
                                </div>
                            </div>
                        ` : `
                            <div class="empty-state">
                                <div class="empty-state-icon">✓</div>
                                <p>No FQDNs discovered</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }

        function renderScrapeTargets(targets) {
            return `
                <div class="findings-section">
                    <div class="section-header">
                        <h2 class="section-title collapsible collapsed" onclick="toggleSection(this)">
                            🎯 Scrape Targets
                        </h2>
                        <span class="severity-badge severity-low">INFO</span>
                    </div>
                    <div class="collapsible-content hidden">
                        ${targets && targets.length > 0 ? targets.map(t => `
                            <div class="finding-item">
                                <div class="finding-type">${t.job}</div>
                                <div style="color: #a8b2d1; margin: 5px 0;">Instance: ${t.instance}</div>
                                <div class="finding-value">${t.scrape_url}</div>
                                <div class="finding-note">Health: ${t.health}</div>
                            </div>
                        `).join('') : `
                            <div class="empty-state">
                                <div class="empty-state-icon">✓</div>
                                <p>No scrape targets discovered</p>
                            </div>
                        `}
                    </div>
                </div>
            `;
        }

        function toggleSection(element) {
            element.classList.toggle('collapsed');
            const content = element.closest('.section-header').nextElementSibling;
            content.classList.toggle('hidden');
        }

        updateUI();
    </script>
</body>
</html>
"""


def create_web_ui(scanner, port=5000):
    app = Flask(__name__)
    CORS(app)
    
    @app.route('/')
    def index():
        scan_time = scanner.scan_start.strftime('%Y-%m-%d %H:%M:%S')
        return render_template_string(HTML_TEMPLATE, target=f"{scanner.host}:{scanner.port}", scan_time=scan_time)
    
    @app.route('/api/data')
    def get_data():
        stats = scanner.get_summary_stats()
        status = scanner.get_status()
        
        critical_findings = [c for c in scanner.findings['credentials'] if c.get('severity') == 'CRITICAL']
        high_findings = [c for c in scanner.findings['credentials'] if c.get('severity') == 'HIGH'] + scanner.findings['secrets']
        dos_vectors = scanner.findings['dos_vectors']
        config_exposure = scanner.findings['config_exposure']
        
        k8s_findings = {}
        for item in scanner.findings['k8s']:
            k8s_type = item['type']
            if k8s_type not in k8s_findings:
                k8s_findings[k8s_type] = []
            k8s_findings[k8s_type].append(item['value'])
        
        containers = {
            'registries': sorted(set(c['value'] for c in scanner.findings['containers'] if c['type'] == 'registry')),
            'images': sorted(set(c['value'] for c in scanner.findings['containers'] if c['type'] == 'image'))
        }
        
        internal_routes = sorted(set(r['route'] for r in scanner.findings['internal_routes']))
        fqdns = sorted(set(f['value'] for f in scanner.findings['fqdns']))
        scrape_targets = scanner.findings['scrape_targets'][:20]
        
        return jsonify({
            'stats': stats,
            'status': status,
            'findings': {
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'dos_vectors': dos_vectors,
                'config_exposure': config_exposure,
                'k8s_findings': k8s_findings,
                'containers': containers,
                'internal_routes': internal_routes,
                'fqdns': fqdns,
                'scrape_targets': scrape_targets
            }
        })
    
    @app.route('/output/<path:filename>')
    def output_file(filename):
        return send_from_directory(scanner.output_dir, filename)
    
    def run_server():
        app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
    
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Web UI available at: {url}")
    webbrowser.open(url)
    
    return app


def main():
    parser = argparse.ArgumentParser(
        description='FireThief - Prometheus Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i 192.168.1.100 -p 9090 --web-ui
  %(prog)s -i prometheus.internal.com -p 9090 -v --save-profiles --web-ui
  %(prog)s -i 10.0.0.50 -p 9090 --web-ui --web-port 8080
        """
    )
    parser.add_argument('-i', '--ip', required=True, help='Target IP or hostname')
    parser.add_argument('-p', '--port', type=int, required=True, help='Target port')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout (default: 10s)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--save-profiles', action='store_true', help='Save downloaded pprof profiles')
    parser.add_argument('-o', '--output', help='Output directory for saved profiles')
    parser.add_argument('--web-ui', action='store_true', help='Launch web UI')
    parser.add_argument('--web-port', type=int, default=5000, help='Web UI port (default: 5000)')
    
    args = parser.parse_args()
    
    scanner = PrometheusScanner(args.ip, args.port, args.timeout, args.verbose, args.save_profiles, args.output)
    
    if args.web_ui:
        create_web_ui(scanner, args.web_port)
        time.sleep(1)
    
    if args.web_ui:
        scan_thread = threading.Thread(target=scanner.run, daemon=False)
        scan_thread.start()
        
        print("\n[*] Scan running... Press Ctrl+C to exit")
        try:
            scan_thread.join()
            print("\n[*] Scan complete. Web UI still available. Press Ctrl+C to exit...")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[+] Shutting down...")
    else:
        scanner.run()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
