# 🔥 FireThief

> "Stealing fire from the Titans" - A comprehensive Prometheus and Go debug endpoint security scanner

FireThief is a security assessment tool designed to discover, enumerate, and analyze Prometheus servers and Go applications with exposed debug endpoints. It identifies sensitive information leakage, credentials exposure, and potential attack vectors in production monitoring infrastructure.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 📋 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [What It Detects](#what-it-detects)
- [Research Background](#research-background)
- [Web Interface](#web-interface)
- [Output Examples](#output-examples)
- [Advanced Usage](#advanced-usage)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [Credits](#credits)

## ✨ Features

### Core Capabilities

- **🔍 Comprehensive Endpoint Discovery** - Automatically discovers 50+ Prometheus and Go debug endpoints
- **📊 Real-time Web Interface** - Live progress tracking and findings visualization
- **🔐 60+ Credential Patterns** - Detects AWS, Azure, GCP, GitHub, GitLab, Slack, Stripe, and many more
- **🐳 Container Intelligence** - Extracts Docker registries, images, and Kubernetes metadata
- **💾 Profile Analysis** - Downloads and decodes pprof heap/CPU/goroutine dumps
- **🌐 Network Mapping** - Validates and extracts FQDNs, internal URLs, and private IPs
- **⚡ DoS Vector Detection** - Identifies unauthenticated endpoints vulnerable to resource exhaustion

### Technical Features

- **Three-phase scanning**: Discovery → Enumeration → Deep Analysis
- **Intelligent FQDN validation** - Filters false positives like `fmt.println`, `log.error`
- **pprof decoding** - Uses `go tool pprof` for binary profile analysis
- **Early termination** - Skips remaining phases if no endpoints are accessible
- **Severity classification** - CRITICAL/HIGH/MEDIUM/LOW risk categorization
- **Profile archiving** - Optional saving of all downloaded profiles

## 🚀 Installation

### Prerequisites

- Python 3.8+
- Go 1.16+ (optional, for pprof decoding)

### Install Dependencies
```bash
# Clone the repository
git clone https://github.com/yourusername/firethief.git
cd firethief

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install Go and pprof for full profile analysis
sudo apt install golang-go

# After installing Go, install pprof
go install github.com/google/pprof@latest
```

### Requirements File

**requirements.txt:**
```
requests>=2.31.0
Flask>=3.0.0
flask-cors>=4.0.0
```

## 🎯 Quick Start
```bash
# Basic scan (single target)
python3 firethief.py -i 192.168.1.100 -p 9090

# Scan with web interface (recommended)
python3 firethief.py -i prometheus.internal.com -p 9090 --web-ui

# Full scan with profile saving and verbose output
python3 firethief.py -i 10.0.0.50 -p 9090 --web-ui --save-profiles -v

# Scan multiple targets from a file
python3 firethief.py -T targets.txt --web-ui

# Multiple targets with verbose output and profile saving
python3 firethief.py -T targets.txt -v --save-profiles
```

## 📖 Usage

### Command Line Options
```
usage: firethief.py [-h] [-i IP] [-p PORT] [-T FILE] [-t TIMEOUT] [-v]
                    [--save-profiles] [-o OUTPUT] [--web-ui]
                    [--web-port WEB_PORT]

FireThief - Prometheus Security Scanner

target arguments (use -i/-p for a single target, or -T for a file of targets):
  -i IP, --ip IP              Target IP or hostname
  -p PORT, --port PORT        Target port
  -T FILE, --targets FILE     File containing targets, one per line in
                              http://ip:port format

optional arguments:
  -h, --help                  Show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT
                              Request timeout in seconds (default: 10)
  -v, --verbose               Verbose output (show all requests)
  --save-profiles             Save downloaded pprof profiles to disk
  -o OUTPUT, --output OUTPUT  Output directory for saved profiles
  --web-ui                    Launch real-time web interface
  --web-port WEB_PORT         Web UI port (default: 5000)
```

### Multi-Target Scanning

Use `-T` / `--targets` to scan multiple hosts from a file. The file should contain one target per line in `http://ip:port` or `https://ip:port` format. Lines starting with `#` are treated as comments.

**Example targets file** (`targets.txt`):
```
# Prometheus instances
http://192.168.1.100:9090
http://10.0.0.50:9090
https://prometheus.internal.com:443
http://172.16.0.1:80
```

```bash
# Scan all targets in the file
python3 firethief.py -T targets.txt

# With web UI — includes a target selector bar for switching between targets
python3 firethief.py -T targets.txt --web-ui

# Mix with other options
python3 firethief.py -T targets.txt -v --save-profiles -t 15
```

Targets are scanned sequentially. In CLI mode, each target gets its own report. In web UI mode, a target navigation bar lets you switch between targets and shows live scan status for each.

## 🔎 What It Detects

### Critical Credentials (60+ Patterns)

| Category | Patterns Detected |
|----------|------------------|
| **Cloud Providers** | AWS (access keys, secrets, session tokens), Azure (client secrets, storage), GCP (API keys) |
| **Version Control** | GitHub (PAT, OAuth, App tokens), GitLab (PAT, runner tokens) |
| **Package Managers** | NPM tokens, PyPI tokens |
| **Communication** | Slack (bot, user, webhook), Discord webhooks, Telegram bot tokens |
| **Payment** | Stripe (live/test keys), Square tokens, PayPal secrets |
| **SaaS APIs** | SendGrid, Twilio, Mailgun, DigitalOcean, Shopify, Datadog, New Relic |
| **Infrastructure** | SSH private keys, PGP keys, SSL/TLS certificates, K8s service account tokens |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch connection strings (with credentials) |
| **Other** | JWT tokens, Bearer tokens, Basic auth URLs, Grafana API keys, Heroku API keys |

### Network & Infrastructure Intelligence

- **FQDNs** - Internal domains (`.local`, `.internal`, `.corp`, `.svc.cluster.local`)
- **Private IPs** - 10.x.x.x, 172.16-31.x.x, 192.168.x.x ranges
- **Internal URLs** - Admin panels, staging environments, internal APIs
- **Container Registries** - Docker Hub, GCR, ECR, ACR, Harbor, Artifactory, Nexus
- **Docker Images** - Image names with tags
- **Kubernetes Metadata** - Namespaces, pods, services, deployments, ingresses, secrets, ConfigMaps

### Prometheus-Specific Findings

- **Scrape Targets** - Internal infrastructure mapping
- **Remote Storage Config** - Potentially containing credentials
- **Alertmanager URLs** - May contain basic auth
- **Configuration Exposure** - Full scrape configs, remote write/read settings

### Attack Vectors

- **DoS Vectors** - Unauthenticated pprof endpoints (CPU/heap profiling abuse)
- **Information Disclosure** - Stack traces, internal routes, file paths
- **Configuration Leakage** - Secrets in metrics labels, environment variables

## 📚 Research Background

FireThief is based on security research from leading cybersecurity organizations:

### Key Research Papers

1. **Aqua Security (Dec 2024)** - [300,000+ Prometheus servers exposed](https://www.aquasec.com/blog/300000-prometheus-servers-and-exporters-exposed-to-dos-attacks/)
   - Identified 300K+ instances vulnerable to DoS attacks
   - Documented credential leakage in metrics and debug endpoints

2. **CyberSRC (Dec 2024)** - [Credentials and API keys leaking online](https://cybersrcc.com/2024/12/18/over-300k-prometheus-instances-exposed-credentials-and-api-keys-leaking-online/)
   - Detailed patterns of AWS, Azure, GCP credential exposure
   - Documented real-world exploitation scenarios

3. **Sysdig** - [Kubernetes exploitation via Prometheus](https://www.sysdig.com/blog/exposed-prometheus-exploit-kubernetes-kubeconeu)
   - Techniques for using exposed Prometheus to compromise K8s clusters
   - Service account token extraction methods

4. **Red Sentry** - [Securing Go applications against pprof exploits](https://redsentry.com/resources/blog/securing-go-applications-against-debug-pprof-exploits)
   - Deep dive into Go pprof internals
   - Stack trace analysis for credential extraction

## 🖥️ Web Interface

FireThief includes a real-time web interface with:

- **Live Progress Tracking** - See scan phases and current actions
- **Dynamic Statistics** - Critical/High/Medium/Low findings counter
- **Collapsible Sections** - All sections start collapsed with result counts in the headline (e.g., "Critical Findings (3)"). Click to expand. Sections you unfold remain open across live data refreshes while the scan is still running.
- **Multi-Target Support** - When scanning multiple targets, a target navigation bar shows all targets with live status indicators. Click to switch between targets.
- **Severity Color Coding** - Red (Critical), Orange (High), Yellow (Medium), Blue (Low)
- **Dark Cyberpunk Theme** - Inspired by professional security tools

### Terminal Output
```
[+] Target: http://prometheus.internal.com:9090
[+] Timeout: 10s
[+] Go pprof: Available

[*] PHASE 1: ENDPOINT DISCOVERY
================================================================================
[+] /debug/pprof/ accessible - parsing index
  [+] Discovered: /debug/pprof/heap
  [+] Discovered: /debug/pprof/goroutine
[+] Prometheus API accessible
[+] Discovery complete: 15 endpoints found

[*] PHASE 2: COMPREHENSIVE SCAN
================================================================================
[+] /debug/pprof/heap (524288 bytes)
[*] Running secret detection on /debug/pprof/heap...
  [+] Valid FQDN found: api.internal.company.com
[+] /api/v1/status/config (2048 bytes)
[*] Running secret detection on /api/v1/status/config...

[*] PHASE 3: DEEP PPROF ANALYSIS
================================================================================
[*] Analyzing pprof profile: /debug/pprof/heap
[+] Downloaded 524288 bytes
[*] Analyzing decompressed binary data (1048576 bytes)
[*] Decoding with 'go tool pprof'...
[+] Successfully decoded 102400 bytes of text
[*] Analyzing decoded text for secrets...

[+] Scan complete in 45.23s

================================================================================
FIRETHIEF SCAN RESULTS
================================================================================

[CRITICAL] Credentials Exposed:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
  DATABASE_URI: postgres://admin:secretpass@db.internal:5432/prod
  GITHUB_PERSONAL_ACCESS_TOKEN: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ... and 9 more

================================================================================
SUMMARY:
  Critical Findings: 12
  High Severity: 45
  DoS Vectors: 3
  K8s Metadata: 23
  FQDNs: 156
================================================================================
```

### Saved Profiles (with `--save-profiles`)
```
firethief_prometheus.internal.com_9090_20250213_143022/
├── debug_pprof_heap.pb.gz
├── debug_pprof_heap_decoded.txt
├── debug_pprof_goroutine.pb.gz
├── debug_pprof_goroutine_decoded.txt
├── debug_pprof_profile.pb.gz
└── debug_pprof_profile_decoded.txt
```

## ⚠️ Disclaimer

**This was 100% vibe-coded using Claude.** That means I know exactly what techniques and design decisions were made, but I barely understand any of the code. That also means if something doesn't work, your best bet is to just throw all of it into an LLM and ask it to fix it. It also means you probably shouldn't use this for anything important or expose it to anyone. **You have been warned.**

Also: Only use this tool on systems you own or have explicit authorization to test. Unauthorized access to computer systems is illegal.

## 🙏 Credits

### Research & Inspiration

- **Aqua Security** - Initial research on Prometheus exposure
- **CyberSRC** - Credential leakage pattern documentation
- **Sysdig** - Kubernetes exploitation techniques
- **Red Sentry** - Go pprof security analysis
- **Prometheus Security Team** - Security model documentation

⭐ If you find this tool useful (or at least amusing), please star the repository!
