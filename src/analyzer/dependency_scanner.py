"""
DependencyScanner
Usa a API OSV.dev (Google) para detetar vulnerabilidades
conhecidas em dependências Python e Node.js.
"""

import json
import requests
from pathlib import Path
from .base_scanner import BaseScanner


class DependencyScanner(BaseScanner):
    name = "Dependency Scanner"

    OSV_API = "https://api.osv.dev/v1/query"

    def scan(self) -> list[dict]:
        findings = []

        for req_file in self.repo_path.rglob("requirements*.txt"):
            if any(p in {".git", "node_modules", "venv"} for p in req_file.parts):
                continue
            findings.extend(self._scan_python_deps(req_file))

        for pkg_file in self.repo_path.rglob("package.json"):
            if any(p in {".git", "node_modules"} for p in pkg_file.parts):
                continue
            findings.extend(self._scan_node_deps(pkg_file))

        return findings

    def _scan_python_deps(self, filepath: Path) -> list[dict]:
        findings = []
        rel = filepath.relative_to(self.repo_path)

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            import re
            match = re.match(r"([a-zA-Z0-9_\-]+)\s*[><=!]+\s*([\d.]+)", line)
            if not match:
                continue

            package = match.group(1)
            version = match.group(2)

            vulns = self._query_osv(package, version, "PyPI")
            for vuln in vulns:
                findings.append(self._make_finding(
                    title=f"Vulnerabilidade em {package}=={version}: {vuln['id']}",
                    severity="HIGH",
                    file=f"{rel}",
                    detail=(
                        f"{vuln.get('summary', 'Sem descrição')} "
                        f"(CVE: {vuln['id']})"
                    ),
                    remediation=(
                        f"Atualiza '{package}' para a versão mais recente. "
                        f"Consulta: https://osv.dev/vulnerability/{vuln['id']}"
                    )
                ))

        return findings

    def _scan_node_deps(self, filepath: Path) -> list[dict]:
        findings = []
        rel = filepath.relative_to(self.repo_path)

        try:
            content = json.loads(filepath.read_text(encoding="utf-8"))
        except Exception:
            return findings

        all_deps = {}
        all_deps.update(content.get("dependencies", {}))
        all_deps.update(content.get("devDependencies", {}))

        for package, version_str in all_deps.items():
            import re
            version = re.sub(r"[^0-9.]", "", version_str)
            if not version:
                continue

            vulns = self._query_osv(package, version, "npm")
            for vuln in vulns:
                findings.append(self._make_finding(
                    title=f"Vulnerabilidade em {package}@{version}: {vuln['id']}",
                    severity="HIGH",
                    file=str(rel),
                    detail=(
                        f"{vuln.get('summary', 'Sem descrição')} "
                        f"(CVE: {vuln['id']})"
                    ),
                    remediation=(
                        f"Atualiza '{package}' para a versão mais recente. "
                        f"Consulta: https://osv.dev/vulnerability/{vuln['id']}"
                    )
                ))

        return findings


    def _query_osv(self, package: str, version: str, ecosystem: str) -> list[dict]:
        """Consulta a API OSV.dev para um pacote e versão específicos."""
        try:
            response = requests.post(
                self.OSV_API,
                json={
                    "version": version,
                    "package": {
                        "name": package,
                        "ecosystem": ecosystem
                    }
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("vulns", [])
        except requests.RequestException:
            pass
        return []