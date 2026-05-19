"""
SecurePipeline Audit Tool
Analisa pipelines CI/CD e deteta más práticas de segurança.

Uso:
    python cli.py --repo ./meu-projeto
"""

import argparse
import json
import sys
from pathlib import Path

from analyzer.secrets_scanner import SecretsScanner
from analyzer.permissions_checker import PermissionsChecker
from analyzer.image_scanner import ImageScanner
from analyzer.dependency_scanner import DependencyScanner
from analyzer.terraform_scanner import TerraformScanner
from report.generator import ReportGenerator


def print_banner():
    print("""
╔═══════════════════════════════════════════╗
║       SecurePipeline Audit Tool           ║
║       Phase 1 — Local Scanner             ║
╚═══════════════════════════════════════════╝
""")


def run_scan(repo_path: str) -> dict:
    path = Path(repo_path)
    if not path.exists():
        print(f"[ERROR] Caminho não encontrado: {repo_path}")
        sys.exit(1)

    print(f"[*] A analisar repositório: {path.resolve()}\n")

    results = {
        "repo": str(path.resolve()),
        "findings": [],
        "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    }

    scanners = [
        SecretsScanner(path),
        PermissionsChecker(path),
        ImageScanner(path),
        DependencyScanner(path),
        TerraformScanner(path)
    ]

    for scanner in scanners:
        print(f"[*] A correr: {scanner.name}...")
        findings = scanner.scan()
        results["findings"].extend(findings)
        for f in findings:
            results["summary"][f["severity"]] += 1
        print(f"    → {len(findings)} finding(s) encontrado(s)\n")

    return results


def print_results(results: dict):
    findings = results["findings"]
    summary = results["summary"]

    print("=" * 50)
    print("RESULTADOS DA AUDITORIA")
    print("=" * 50)

    if not findings:
        print("\n✅ Nenhum problema encontrado!\n")
        return

    severity_colors = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[31m",
        "MEDIUM":   "\033[93m",
        "LOW":      "\033[94m",
    }
    RESET = "\033[0m"

    for f in findings:
        color = severity_colors.get(f["severity"], "")
        print(f"\n{color}[{f['severity']}]{RESET} {f['title']}")
        print(f"  Ficheiro : {f['file']}")
        print(f"  Detalhe  : {f['detail']}")
        print(f"  Fix      : {f['remediation']}")

    print("\n" + "=" * 50)
    print("SUMÁRIO")
    print("=" * 50)
    for severity, count in summary.items():
        if count > 0:
            color = severity_colors.get(severity, "")
            print(f"  {color}{severity}{RESET}: {count}")
    print()


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="SecurePipeline Audit Tool")
    parser.add_argument("--repo", required=True, help="Caminho para o repositório")
    parser.add_argument("--json", action="store_true", help="Output em JSON")
    parser.add_argument("--pdf", type=str, help="Gera relatório PDF no caminho indicado")  # ← aqui
    args = parser.parse_args()

    results = run_scan(args.repo)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results)

    
    if args.pdf:
        print(f"\n[*] A gerar relatório PDF...")
        generator = ReportGenerator()
        pdf_path = generator.generate(results, args.pdf)
        print(f"[+] Relatório guardado em: {pdf_path}\n")

    if results["summary"]["CRITICAL"] > 0:
        sys.exit(2)
    elif results["summary"]["HIGH"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()