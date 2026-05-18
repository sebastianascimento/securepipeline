import re
import yaml
from pathlib import Path
from .base_scanner import BaseScanner


class ImageScanner(BaseScanner):
    name = "Image Scanner"

    def scan(self) -> list[dict]:
        findings = []
        for dockerfile in self.repo_path.rglob("Dockerfile*"):
            if any(p in {".git", "node_modules"} for p in dockerfile.parts):
                continue
            if dockerfile.is_file():
                findings.extend(self._check_dockerfile(dockerfile))
        for compose in self.repo_path.rglob("docker-compose*.yml"):
            if compose.is_file():
                findings.extend(self._check_compose(compose))
        return findings

    def _check_dockerfile(self, filepath: Path) -> list[dict]:
        findings = []
        rel = filepath.relative_to(self.repo_path)
        try:
            lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return findings

        has_user = False
        has_from = False

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            instruction = parts[0].upper()

            if instruction == "FROM" and "AS" not in stripped.upper():
                has_from = True
                image = parts[1] if len(parts) > 1 else ""
                if image != "scratch":
                    if ":" not in image:
                        findings.append(self._make_finding(
                            title=f"Imagem sem tag: {image}",
                            severity="MEDIUM",
                            file=f"{rel}:{line_num}",
                            detail=f"FROM {image} usa implicitamente :latest.",
                            remediation=f"Fixa a versão: 'FROM {image}:X.Y.Z'."
                        ))
                    elif image.endswith(":latest"):
                        findings.append(self._make_finding(
                            title=f"Imagem com :latest: {image}",
                            severity="MEDIUM",
                            file=f"{rel}:{line_num}",
                            detail=f"FROM {image} não é reproduzível.",
                            remediation="Substitui :latest por uma versão específica."
                        ))

            if instruction == "USER":
                has_user = True
                user_val = parts[1] if len(parts) > 1 else ""
                if user_val in ("root", "0"):
                    findings.append(self._make_finding(
                        title="Container configurado para correr como root",
                        severity="HIGH",
                        file=f"{rel}:{line_num}",
                        detail="USER root dá privilégios de root ao processo dentro do container.",
                        remediation="Cria um utilizador: 'RUN useradd -m appuser && USER appuser'."
                    ))

            if instruction in ("ARG", "ENV"):
                rest = stripped[len(instruction):].strip()
                if re.search(r"(?i)(password|secret|token|key|api_key)\s*=", rest):
                    findings.append(self._make_finding(
                        title=f"Possível segredo em {instruction}",
                        severity="HIGH",
                        file=f"{rel}:{line_num}",
                        detail=f"'{stripped[:80]}' — visível no histórico da imagem.",
                        remediation="Usa Docker BuildKit secrets em vez de ARG/ENV para credenciais."
                    ))

            if instruction == "ADD":
                rest = stripped[4:].strip()
                if not re.match(r"https?://", rest) and not rest.endswith((".tar", ".tar.gz", ".tgz")):
                    findings.append(self._make_finding(
                        title="ADD para ficheiro local — usa COPY",
                        severity="LOW",
                        file=f"{rel}:{line_num}",
                        detail="ADD tem comportamento extra não-óbvio para ficheiros locais.",
                        remediation="Substitui ADD por COPY para ficheiros locais."
                    ))

        if has_from and not has_user:
            findings.append(self._make_finding(
                title="Dockerfile sem instrução USER",
                severity="MEDIUM",
                file=str(rel),
                detail="Sem USER definido, o processo corre como root por defeito.",
                remediation="Adiciona 'RUN useradd -m appuser' e 'USER appuser' antes do CMD."
            ))

        return findings

    def _check_compose(self, filepath: Path) -> list[dict]:
        findings = []
        rel = filepath.relative_to(self.repo_path)
        try:
            compose = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        except Exception:
            return findings
        if not isinstance(compose, dict):
            return findings
        for name, service in (compose.get("services", {}) or {}).items():
            if not isinstance(service, dict):
                continue
            if service.get("privileged"):
                findings.append(self._make_finding(
                    title=f"Serviço '{name}' em modo privileged",
                    severity="CRITICAL",
                    file=str(rel),
                    detail=f"'{name}' tem 'privileged: true' — acesso total ao host.",
                    remediation="Remove 'privileged: true'. Usa 'cap_add' para capabilities específicas."
                ))
            for port in (service.get("ports", []) or []):
                if re.match(r"^\d+:\d+$", str(port)):
                    findings.append(self._make_finding(
                        title=f"Serviço '{name}' exposto em todas as interfaces",
                        severity="LOW",
                        file=str(rel),
                        detail=f"Porta '{port}' exposta em 0.0.0.0.",
                        remediation=f"Restringe: '127.0.0.1:{port}'."
                    ))
        return findings