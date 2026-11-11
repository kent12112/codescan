"""Scan stages. Everything here runs inside a container, never on the operator host.

Scanner Job (image: codescan-scanner)
    entrypoint      wait for network isolation, unpack the source bundle, run pipeline.py
    workspace       throwaway copy of the target; shared skip list
    semgrep_scan    Semgrep (native engine adapter: native_semgrep)
    injection       deterministic prompt-injection pre-flags
    analyst_client  mTLS call to the contained analyst Pod
    zap_report      fold an optional ZAP (DAST) report into the findings
    synthesize      LLM merge + deterministic authority backstop

Analyst Pod (image: codescan-agent, served by service/analyst.py)
    analyst_agent   guarded tool loop: code review + check_cve via the OSV broker
    egress_filter   body check on every outbound tool call

Shared
    llm_client      Anthropic client that talks only to the mTLS LLM gateway
"""
