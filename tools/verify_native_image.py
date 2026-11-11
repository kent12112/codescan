"""Run inside the scanner image with the bundled demonstration source mounted."""
import importlib.util
from pathlib import Path
from codescan.semgrep_scan import run_semgrep


def main():
    assert importlib.util.find_spec('semgrep') is None, 'Python CLI leaked into runtime'
    assert importlib.util.find_spec('opentelemetry') is None, 'telemetry leaked into runtime'
    findings = run_semgrep(Path('/target'))
    if not any(finding['severity'] == 'HIGH' for finding in findings):
        raise RuntimeError('native engine missed the vulnerable sample')
    print('Native scanner sample passed:', len(findings), 'findings')


if __name__ == '__main__':
    main()
