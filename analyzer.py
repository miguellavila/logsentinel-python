"""Analyze Apache/Nginx combined access logs without contacting any host."""
from __future__ import annotations
import argparse
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+) [^\"]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: .*)?$'
)
SENSITIVE = re.compile(r'/(?:\.env|\.git|wp-admin|admin|phpmyadmin)(?:/|$)', re.I)

@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    source_ip: str
    count: int
    description: str

def analyze(lines: list[str], threshold: int = 5) -> dict:
    if threshold < 1:
        raise ValueError('threshold deve ser maior que zero')
    bad_auth = Counter()
    errors = Counter()
    sensitive = Counter()
    status_counts = Counter()
    malformed = 0
    total = 0
    for line in lines:
        if not line.strip():
            continue
        match = LOG_PATTERN.match(line.rstrip('\n'))
        if not match:
            malformed += 1
            continue
        total += 1
        ip, status = match['ip'], int(match['status'])
        status_counts[str(status)] += 1
        if status in (401, 403):
            bad_auth[ip] += 1
        if status >= 500:
            errors[ip] += 1
        path = urlsplit(match['path']).path
        if SENSITIVE.search(path):
            sensitive[ip] += 1
    findings: list[Finding] = []
    for ip, count in bad_auth.items():
        if count >= threshold:
            findings.append(Finding('auth_failures', 'medium', ip, count, 'Muitas respostas 401/403 no arquivo analisado'))
    for ip, count in sensitive.items():
        findings.append(Finding('sensitive_paths', 'medium', ip, count, 'Requisições a caminhos administrativos ou sensíveis'))
    for ip, count in errors.items():
        if count >= threshold:
            findings.append(Finding('server_errors', 'low', ip, count, 'Alta quantidade de respostas 5xx'))
    findings.sort(key=lambda x: (x.category, -x.count, x.source_ip))
    return {'parsed_requests': total, 'malformed_lines': malformed,
            'status_counts': dict(sorted(status_counts.items())),
            'findings': [asdict(f) for f in findings],
            'note': 'Heurísticas sobre o arquivo completo; não comprovam ataques nem medem taxa temporal.'}

def main() -> int:
    parser = argparse.ArgumentParser(description='Análise offline de logs web')
    parser.add_argument('logfile', type=Path)
    parser.add_argument('--threshold', type=int, default=5, help='limiar de ocorrências por IP')
    parser.add_argument('--output', type=Path, help='salvar JSON em arquivo')
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error('--threshold precisa ser >= 1')
    try:
        with args.logfile.open(encoding='utf-8', errors='replace') as stream:
            report = analyze(stream, args.threshold)
        result = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(result + '\n', encoding='utf-8')
        else:
            print(result)
    except OSError as error:
        parser.exit(1, f'Erro de arquivo: {error}\n')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
