"""
FireThief - Web UI server for real-time scan visualization.
"""

import logging
import threading
import time
import webbrowser
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS


def create_web_ui(scanners, port=5000):
    if not isinstance(scanners, list):
        scanners = [scanners]

    app = Flask(__name__)
    CORS(app)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    @app.route('/')
    def index():
        targets_list = [s.base_url for s in scanners]
        return render_template('index.html', targets=targets_list)

    @app.route('/api/targets')
    def get_targets():
        result = []
        for s in scanners:
            has_critical = any(c.get('severity') == 'CRITICAL' for c in s.findings['credentials'])
            has_endpoints = len(s.findings['accessible_endpoints']) > 0
            stats = s.get_summary_stats()
            has_findings = (stats['critical'] + stats['high'] + stats['medium']
                           + stats['dos_vectors'] + len(s.findings['secrets'])) > 0

            if has_critical:
                dot = 'red'
            elif has_findings:
                dot = 'orange'
            elif has_endpoints:
                dot = 'green'
            else:
                dot = 'blue'

            result.append({
                'url': s.base_url,
                'status': s.scan_status,
                'progress': s.progress_percent,
                'dot': dot,
            })
        return jsonify(result)

    @app.route('/api/data')
    def get_data():
        idx = request.args.get('target', 0, type=int)
        if idx < 0 or idx >= len(scanners):
            idx = 0
        scanner = scanners[idx]

        stats = scanner.get_summary_stats()
        status = scanner.get_status()

        critical_findings = [c for c in scanner.findings['credentials'] if c.get('severity') == 'CRITICAL']
        high_findings_list = [c for c in scanner.findings['credentials'] if c.get('severity') == 'HIGH'] + scanner.findings['secrets']
        high_findings_grouped = {}
        for f in high_findings_list:
            t = f.get('type', 'unknown')
            if t not in high_findings_grouped:
                high_findings_grouped[t] = []
            high_findings_grouped[t].append(f)
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
                'high_findings': high_findings_grouped,
                'dos_vectors': dos_vectors,
                'config_exposure': config_exposure,
                'k8s_findings': k8s_findings,
                'containers': containers,
                'internal_routes': internal_routes,
                'fqdns': fqdns,
                'scrape_targets': scrape_targets,
                'infrastructure': scanner.findings['infrastructure']
            }
        })

    def run_server():
        app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1)

    url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Web UI available at: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass

    return app
