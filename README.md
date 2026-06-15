# SecurePipeline Audit Tool

> Ferramenta de auditoria automatizada de segurança para pipelines CI/CD e infraestrutura — deteta segredos expostos, permissões excessivas, más configurações em Docker, Terraform e dependências vulneráveis.

[![CI/CD](https://github.com/sebastianascimento/securepipeline/actions/workflows/deploy.yml/badge.svg)](https://github.com/sebastianascimento/securepipeline/actions)

---

## 🎯 O problema que resolve

Equipas de desenvolvimento publicam código rapidamente e deixam vulnerabilidades para trás: passwords e API keys hardcoded, workflows do GitHub Actions com permissões excessivas, imagens Docker sem versão fixada ou a correr como root, infraestrutura Terraform com más configurações, e dependências com vulnerabilidades conhecidas (CVEs).

O **SecurePipeline Audit Tool** automatiza esta deteção — o mesmo tipo de trabalho que uma auditoria de segurança faz manualmente para clientes.

---

## 🔍 O que analisa

| Scanner | O que deteta |
|---|---|
| **Secrets Scanner** | Passwords, API keys, tokens, connection strings, private keys hardcoded |
| **Permissions Checker** | Permissões excessivas em GitHub Actions, `pull_request_target` perigoso, actions sem hash fixado |
| **Image Scanner** | Imagens `:latest`, containers a correr como root, segredos em ARG/ENV, `docker-compose` em modo privileged |
| **Dependency Scanner** | Vulnerabilidades conhecidas (CVEs) em `requirements.txt` e `package.json` via OSV.dev |
| **Terraform Scanner** | Más configurações de infraestrutura via Checkov |

---

## 🚀 Como usar

```bash
# Clonar o repositório
git clone https://github.com/sebastianascimento/securepipeline.git
cd securepipeline/src

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt

# Correr a auditoria
python cli.py --repo ./tests/

# Gerar relatório PDF
python cli.py --repo ./tests/ --pdf relatorio.pdf

# Output em JSON (para integrar noutras ferramentas)
python cli.py --repo ./tests/ --json
```

---

## ⚙️ Exit codes (integração CI/CD)

| Código | Significado |
|---|---|
| `0` | Sem findings CRITICAL ou HIGH |
| `1` | Findings HIGH encontrados |
| `2` | Findings CRITICAL encontrados |

Permite que o pipeline falhe automaticamente se for detetado um problema grave.

---

## 🔄 CI/CD Pipeline

A cada push para `develop`, o GitHub Actions:

1. Corre os 5 scanners no próprio código do projeto
2. Guarda os resultados como artefacto
3. Builda a imagem Docker
4. Publica a imagem no Docker Hub

Arquitetura extensível — adicionar um scanner novo é criar uma classe que herda de `BaseScanner` e adicionar uma linha no `cli.py`.

---

## 🛠️ Stack técnica

Python · PyYAML · Checkov · OSV.dev API · WeasyPrint · Docker · GitHub Actions · Terraform · Azure

---

## 📌 Roadmap

- [x] Core scanner (secrets, permissions, Docker)
- [x] Integração OSV.dev + Checkov
- [x] Relatório PDF profissional
- [x] CI/CD com Docker Hub
- [ ] Suporte a GitLab CI
- [ ] Dashboard web com histórico de scans

---

*Projeto de portfólio focado em DevSecOps e Application Security.*