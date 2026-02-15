"""
FireThief - Pattern definitions for credential and infrastructure detection.
"""

import re

# Data-driven credential detection: (pattern_key, type_name, match_group, truncate_len, severity)
CREDENTIAL_RULES = [
    # Cloud providers
    ('aws_key',              'AWS_ACCESS_KEY_ID',              1,    None, 'CRITICAL'),
    ('aws_secret',           'AWS_SECRET_ACCESS_KEY',          2,    20,   'CRITICAL'),
    ('aws_session',          'AWS_SESSION_TOKEN',              2,    30,   'CRITICAL'),
    ('azure_client_secret',  'AZURE_CLIENT_SECRET',            2,    20,   'CRITICAL'),
    ('azure_storage',        'AZURE_STORAGE_CONNECTION_STRING', 0,   50,   'CRITICAL'),
    ('gcp_api_key',          'GCP_API_KEY',                    0,    None, 'CRITICAL'),
    # Version control
    ('github_pat',           'GITHUB_PERSONAL_ACCESS_TOKEN',   0,    None, 'CRITICAL'),
    ('github_oauth',         'GITHUB_OAUTH_TOKEN',             0,    None, 'CRITICAL'),
    ('github_app',           'GITHUB_APP_TOKEN',               0,    None, 'CRITICAL'),
    ('github_fine_grained',  'GITHUB_FINE_GRAINED_PAT',        0,    50,   'CRITICAL'),
    ('github_refresh',       'GITHUB_REFRESH_TOKEN',           0,    None, 'CRITICAL'),
    ('gitlab_pat',           'GITLAB_PERSONAL_ACCESS_TOKEN',   0,    None, 'CRITICAL'),
    ('gitlab_runner',        'GITLAB_RUNNER_TOKEN',            0,    None, 'CRITICAL'),
    # Package managers
    ('npm_token',            'NPM_ACCESS_TOKEN',               0,    None, 'CRITICAL'),
    ('pypi_token',           'PYPI_API_TOKEN',                 0,    50,   'CRITICAL'),
    # Communication
    ('slack_bot_token',      'SLACK_BOT_TOKEN',                0,    None, 'CRITICAL'),
    ('slack_user_token',     'SLACK_USER_TOKEN',               0,    None, 'CRITICAL'),
    ('slack_workspace',      'SLACK_WORKSPACE_TOKEN',          0,    None, 'CRITICAL'),
    ('slack_webhook',        'SLACK_WEBHOOK_URL',              0,    None, 'HIGH'),
    ('discord_webhook',      'DISCORD_WEBHOOK_URL',            0,    None, 'MEDIUM'),
    # Payment
    ('stripe_live_secret',   'STRIPE_LIVE_SECRET_KEY',         0,    30,   'CRITICAL'),
    ('stripe_test_secret',   'STRIPE_TEST_SECRET_KEY',         0,    30,   'HIGH'),
    ('stripe_live_pub',      'STRIPE_LIVE_PUBLISHABLE_KEY',    0,    30,   'HIGH'),
    ('stripe_restricted',    'STRIPE_RESTRICTED_KEY',          0,    30,   'CRITICAL'),
    ('square_access',        'SQUARE_ACCESS_TOKEN',            0,    None, 'CRITICAL'),
    ('square_oauth',         'SQUARE_OAUTH_SECRET',            0,    None, 'CRITICAL'),
    # SaaS APIs
    ('twilio_account_sid',   'TWILIO_ACCOUNT_SID',             0,    None, 'HIGH'),
    ('twilio_api_key',       'TWILIO_API_KEY',                 0,    None, 'CRITICAL'),
    ('sendgrid_api',         'SENDGRID_API_KEY',               0,    30,   'CRITICAL'),
    ('digitalocean_pat',     'DIGITALOCEAN_PERSONAL_ACCESS_TOKEN', 0, 30, 'CRITICAL'),
    ('digitalocean_oauth',   'DIGITALOCEAN_OAUTH_TOKEN',       0,    30,   'CRITICAL'),
    ('digitalocean_refresh', 'DIGITALOCEAN_REFRESH_TOKEN',     0,    30,   'CRITICAL'),
    ('shopify_token',        'SHOPIFY_ACCESS_TOKEN',           0,    None, 'CRITICAL'),
    ('shopify_shared',       'SHOPIFY_SHARED_SECRET',          0,    None, 'CRITICAL'),
    ('shopify_custom',       'SHOPIFY_CUSTOM_APP_TOKEN',       0,    None, 'CRITICAL'),
    ('shopify_private',      'SHOPIFY_PRIVATE_APP_TOKEN',      0,    None, 'CRITICAL'),
    ('mailgun_api',          'MAILGUN_API_KEY',                0,    None, 'CRITICAL'),
    ('mailgun_signing',      'MAILGUN_SIGNING_KEY',            0,    None, 'CRITICAL'),
    ('heroku_api',           'HEROKU_API_KEY',                 0,    None, 'HIGH'),
    ('atlassian_api',        'ATLASSIAN_API_TOKEN',            1,    None, 'CRITICAL'),
    ('datadog_api',          'DATADOG_API_KEY',                0,    None, 'CRITICAL'),
    ('datadog_app',          'DATADOG_APP_KEY',                0,    None, 'CRITICAL'),
    ('newrelic_api',         'NEWRELIC_API_KEY',               0,    None, 'CRITICAL'),
    ('newrelic_insights',    'NEWRELIC_INSIGHTS_KEY',          0,    None, 'CRITICAL'),
    ('pagerduty_api',        'PAGERDUTY_API_KEY',              0,    None, 'HIGH'),
    ('grafana_key',          'GRAFANA_API_KEY',                0,    None, 'HIGH'),
    ('grafana_service_account', 'GRAFANA_SERVICE_ACCOUNT_TOKEN', 0, None, 'HIGH'),
    ('generic_api_key',      'GENERIC_API_KEY',                1,    30,   'MEDIUM'),
    # Databases
    ('db_uri',               'DATABASE_URI',                   0,    None, 'CRITICAL'),
    ('jdbc_with_creds',      'JDBC_URL_WITH_CREDENTIALS',      0,    None, 'CRITICAL'),
    ('jdbc_url',             'JDBC_URL',                       0,    None, 'HIGH'),
    ('odbc_connection',      'ODBC_CONNECTION_STRING',         0,    100,  'CRITICAL'),
    ('odbc_dsn',             'ODBC_DSN_CONNECTION',            0,    100,  'CRITICAL'),
    ('sqlalchemy_url',       'SQLALCHEMY_URL',                 0,    None, 'CRITICAL'),
    ('mongodb_atlas',        'MONGODB_ATLAS_CONNECTION',       0,    None, 'CRITICAL'),
    ('mongodb_srv',          'MONGODB_SRV_CONNECTION',         0,    None, 'CRITICAL'),
    ('connection_string',    'CONNECTION_STRING_WITH_CREDENTIALS', 0, None, 'CRITICAL'),
    # Auth tokens
    ('jwt',                  'JWT_TOKEN',                      0,    100,  'HIGH'),
    ('bearer_token',         'BEARER_TOKEN',                   1,    50,   'HIGH'),
    ('basic_auth_url',       'BASIC_AUTH_URL',                 0,    None, 'CRITICAL'),
    # Webhooks
    ('webhook',              'WEBHOOK_URL',                    0,    None, 'MEDIUM'),
    # Infrastructure
    ('pgp_private_key',      'PGP_PRIVATE_KEY',               0,    None, 'CRITICAL'),
]


def compile_patterns() -> dict:
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
        'private_ip': re.compile(
            r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3})\b'
        ),
        'route_handler': re.compile(r'(?:Handler|handleFunc|ServeHTTP|http\.).*?([/][a-z0-9/_\-{}]+)'),
        'webhook': re.compile(
            r'https?://(?:hooks\.slack\.com|discord\.com/api/webhooks|'
            r'outlook\.office\.com/webhook|api\.telegram\.org/bot)[^\s"\'<>\]]+',
            re.IGNORECASE
        ),
        'discord_webhook': re.compile(r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
        'env_var_secret': re.compile(r'(?:export\s+)?([A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL))=([^\s]+)'),
    }
