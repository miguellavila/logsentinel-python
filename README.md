# LogSentinel — Analisador de Logs Web

Ferramenta **Python**, sem dependências externas, para identificar padrões que merecem investigação em logs Apache/Nginx no formato *combined*.

## Funcionalidades

- Contagem de códigos HTTP e linhas não reconhecidas.
- Agrupamento de respostas 401/403 por IP.
- Identificação de acessos a caminhos administrativos e potencialmente sensíveis.
- Contagem de respostas 5xx por IP.
- Relatório JSON utilizável em automações.

## Como executar

    python analyzer.py sample_access.log --threshold 5
    python analyzer.py sample_access.log --output relatorio.json
    python -m unittest discover -s tests -v

**Limitações:** é uma análise heurística offline; não valida se houve invasão, não diferencia IPs compartilhados e não calcula taxa por intervalo de tempo. O log de exemplo usa endereços reservados à documentação.

## Tecnologias
Python 3.10+, biblioteca padrão, regex, JSON, unittest.
