"""
TerraformScanner
Usa o Checkov para analisar ficheiros Terraform (.tf)
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

    def scan(self) -> list[dict]:
        findings = []

        tf_files = list(self.repo_path.rglob("*.tf"))
        tf_files = [f for f in tf_files if ".git" not in str(f)]

        if not tf_files:
            return findings

        if not self._checkov_available():
            findings.append(self._make_finding(
                title="Checkov não instalado — scan Terraform ignorado",
                severity="LOW",
                file="N/A",
                detail="O Checkov é necessário para analisar ficheiros Terraform.",
                remediation="Instala com: pip install checkov"
            ))
            return findings

        findings.extend(self._run_checkov())
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

            if isinstance(data, list):
                checks = data
            else:
                checks = [data]

            for check_result in checks:
                failed = check_result.get("results", {}).get("failed_checks", [])
                for check in failed:
                    severity = self.SEVERITY_MAP.get(
                        check.get("severity", "MEDIUM"), "MEDIUM"
                    )
                    findings.append(self._make_finding(
                        title=f"Terraform: {check.get('check_id')} — {check.get('check_type', '')}",
                        severity=severity,
                        file=f"{check.get('repo_file_path', 'N/A')}:{check.get('file_line_range', ['?'])[0]}",
                        detail=check.get("check_id", ""),
                        remediation=(
                            f"Consulta: https://docs.bridgecrew.io/docs/{check.get('check_id', '').lower()}"
                        )
                    ))

        except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception):
            pass

        return findings