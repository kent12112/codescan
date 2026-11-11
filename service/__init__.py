"""Mutually authenticated HTTPS services (Gunicorn apps, see gunicorn_config.py).

analyst       POST /analyze for the scanner identity; wraps codescan.analyst_agent
gateway       POST /v1/messages; the only holder of the provider key (policy: gateway_policy, quota)
osv_broker    POST /v1/query for the analyst identity; body policy in osv_policy
common        workload identity from the client certificate; bounded JSON requests
findings      validation of analyst output (shared with the scanner's analyst_client)
strict_json   duplicate-key-rejecting JSON parser used by every boundary
"""
