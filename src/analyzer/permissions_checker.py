import re
import yaml
from pathlib import Path
from .base_scanner import BaseScanner


class PermissionsChecker(BaseScanner):
    name = "Permissions Checker"

    def scan(self) -> list[dict]:
        findings = []
        workflows_path = self.repo_path / ".github" / "workflows"
        if not workflows_path.exists():
            return findings
        for wf in list(workflows_path.glob("*.yml")) + list(workflows_path.glob("*.yaml")):
            findings.extend(self._check_workflow(wf))
        return findings

    def _check_workflow(self, filepath: Path) -> list[dict]:
        findings = []
        try:
            content = filepath.read_text(encoding="utf-8")
            workflow = yaml.safe_load(content)
        except Exception:
            return findings

        if not isinstance(workflow, dict):
            return findings

        rel = filepath.relative_to(self.repo_path)

        perms = workflow.get("permissions")
        if perms == "write-all":
            findings.append(self._make_finding(
                title="Permissões excessivas: write-all",
                severity="HIGH",
                file=str(rel),
                detail="O workflow tem 'permissions: write-all' — acesso de escrita a todos os escopos.",
                remediation="Define permissões mínimas: 'permissions: { contents: read }'."
            ))
        elif perms is None:
            findings.append(self._make_finding(
                title="Permissões não definidas explicitamente",
                severity="MEDIUM",
                file=str(rel),
                detail="Sem 'permissions' definido, herda as permissões padrão do repositório.",
                remediation="Adiciona 'permissions: read-all' no topo do workflow."
            ))

        triggers = workflow.get("on", {})
        has_prt = (
            (isinstance(triggers, dict) and "pull_request_target" in triggers) or
            (isinstance(triggers, list) and "pull_request_target" in triggers)
        )
        if has_prt:
            for job_name, job in (workflow.get("jobs", {}) or {}).items():
                for step in (job.get("steps", []) if isinstance(job, dict) else []):
                    if isinstance(step, dict) and step.get("run"):
                        findings.append(self._make_finding(
                            title="pull_request_target com run — risco de injeção",
                            severity="CRITICAL",
                            file=str(rel),
                            detail=f"Job '{job_name}' executa código de PR externo com permissões elevadas.",
                            remediation="Separa o checkout da execução. Usa pull_request em vez de pull_request_target."
                        ))
                        break

        for job_name, job in (workflow.get("jobs", {}) or {}).items():
            if not isinstance(job, dict):
                continue
            for step in (job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if uses and "@" in uses:
                    version = uses.split("@")[-1]
                    is_pinned = bool(re.match(r"^[0-9a-f]{40}$", version))
                    if not is_pinned:
                        findings.append(self._make_finding(
                            title=f"Action não fixada por commit hash: {uses}",
                            severity="MEDIUM",
                            file=str(rel),
                            detail=f"'{uses}' usa uma tag que pode ser alterada para apontar para código malicioso.",
                            remediation=f"Fixa pelo hash SHA: '{uses.split('@')[0]}@<SHA>'."
                        ))
        return findings