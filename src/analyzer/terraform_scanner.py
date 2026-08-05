"""
TerraformScanner
Usa o Checkov e o tfsec para analisar ficheiros Terraform (.tf)
e detetar más configurações de segurança.
"""

import subprocess
import json
from pathlib import Path
from .base_scanner import BaseScanner


class TerraformScanner(BaseScanner):
    name = "Terraform Scanner"

    SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
        "INFO":     "LOW",
    }

    TFSEC_SEVERITY_MAP = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
    }

    def scan(self) -> list[dict]:
        findings = []

        tf_files = list(self.repo_path.rglob("*.tf"))
        tf_files = [f for f in tf_files if ".git" not in str(f)]

        if not tf_files:
            return findings

        # Checkov
        if self._checkov_available():
            findings.extend(self._run_checkov())
        else:
            findings.append(self._make_finding(
                title="Checkov não instalado — scan Terraform parcial",
                severity="LOW",
                file="N/A",
                detail="O Checkov é necessário para análise completa de Terraform.",
                remediation="Instala com: pip install checkov"
            ))

        # tfsec
        if self._tfsec_available():
            findings.extend(self._run_tfsec())
        else:
            findings.append(self._make_finding(
                title="tfsec não instalado — scan Terraform parcial",
                severity="LOW",
                file="N/A",
                detail="O tfsec deteta más configurações específicas de Terraform.",
                remediation="Instala com: brew install tfsec (Mac) ou https://github.com/aquasecurity/tfsec"
            ))

        return findings



    def _checkov_available(self) -> bool:
        try:
            subprocess.run(
                ["checkov", "--version"],
                capture_output=True,
                timeout=10
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_checkov(self) -> list[dict]:
        findings = []
        try:
            result = subprocess.run(
                [
                    "checkov",
                    "--directory", str(self.repo_path),
                    "--output", "json",
                    "--quiet",
                    "--framework", "terraform"
                ],
                capture_output=True,
                text=True,
                timeout=120
            )

            output = result.stdout
            if not output:
                return findings

            data = json.loads(output)
            checks = data if isinstance(data, list) else [data]

            for check_result in checks:
                failed = check_result.get("results", {}).get("failed_checks", [])
                for check in failed:
                    severity = self.SEVERITY_MAP.get(
                        check.get("severity", "MEDIUM"), "MEDIUM"
                    )
                    findings.append(self._make_finding(
                        title=f"[Checkov] {check.get('check_id')} — {check.get('check_type', '')}",
                        severity=severity,
                        file=f"{check.get('repo_file_path', 'N/A')}:{check.get('file_line_range', ['?'])[0]}",
                        detail=check.get("check_id", ""),
                        remediation=f"Consulta: https://docs.bridgecrew.io/docs/{check.get('check_id', '').lower()}"
                    ))

        except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
            pass

        return findings


    def _tfsec_available(self) -> bool:
        try:
            subprocess.run(
                ["tfsec", "--version"],
                capture_output=True,
                timeout=10
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_tfsec(self) -> list[dict]:
        findings = []
        try:
            result = subprocess.run(
                [
                    "tfsec",
                    str(self.repo_path),
                    "--format", "json",
                    "--no-color",
                ],
                capture_output=True,
                text=True,
                timeout=120
            )

            output = result.stdout
            if not output:
                return findings

            data = json.loads(output)
            results = data.get("results", [])

            for issue in results:
                severity = self.TFSEC_SEVERITY_MAP.get(
                    issue.get("severity", "MEDIUM").upper(), "MEDIUM"
                )
                location = issue.get("location", {})
                filename = location.get("filename", "N/A")
                start_line = location.get("start_line", "?")

                findings.append(self._make_finding(
                    title=f"[tfsec] {issue.get('rule_id', '')} — {issue.get('rule_summary', '')}",
                    severity=severity,
                    file=f"{filename}:{start_line}",
                    detail=issue.get("description", ""),
                    remediation=issue.get("impact", "Consulta a documentação do tfsec.")
                ))

        except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
            pass

        return findings