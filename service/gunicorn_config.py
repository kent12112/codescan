"""One bounded worker pool; mutual TLS is mandatory and certs reload per handshake."""
import os
import ssl

bind = os.environ.get('SERVICE_BIND', '0.0.0.0:8443')
workers = 1
worker_class = 'gthread'
threads = int(os.environ.get('SERVICE_THREADS', '4'))
worker_connections = 16
backlog = 16
timeout = 300
graceful_timeout = 30
keepalive = 2
limit_request_line = 1024
limit_request_fields = 32
limit_request_field_size = 4096
forwarded_allow_ips = ''
accesslog = None
errorlog = '-'
loglevel = 'warning'
certfile = os.environ.get('TLS_CERT_FILE', '/etc/workload-tls/tls.crt')
keyfile = os.environ.get('TLS_KEY_FILE', '/etc/workload-tls/tls.key')
ca_certs = os.environ.get('TLS_CA_FILE', '/etc/workload-tls/ca.crt')
cert_reqs = ssl.CERT_REQUIRED


def ssl_context(conf, default_ssl_context_factory):
    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
