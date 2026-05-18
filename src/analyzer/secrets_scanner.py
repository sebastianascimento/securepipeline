import re
from pathlib import Path
from .base_scanner import BaseScanner


SECRET_PATTERNS = [
    ("AWS Access Key",       r"AKIA[0-9A-Z]{16}",                                        "CRITICAL"),
    ("AWS Secret Key",       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    ("GitHub Token",         r"ghp_[a-zA-Z0-9]{36}",                                     "CRITICAL"),
    ("GitHub Actions Token", r"ghs_[a-zA-Z0-9]{36}",                                     "CRITICAL"),
    ("Slack Token",          r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",                         "HIGH"),
    ("Generic API Key",      r"(?i)(api_key|apikey)\s*=\s*['\"][^'\"]{8,}['\"]",         "HIGH"),
    ("Generic Password",     r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",    "HIGH"),
    ("Generic Secret",       r"(?i)(secret|token)\s*=\s*['\"][^'\"]{8,}['\"]",           "HIGH"),
    ("Private Key Header",   r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",          "CRITICAL"),
    ("Database URL",         r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@",        "CRITICAL"),
    ("Connection String",    r"(?i)Server=.+;Database=.+;User Id=.+;Password=",           "HIGH"),
    ("Bearer Token",         r"(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]{20,}",  "MEDIUM"),
]

INCLUDE_EXTENSIONS = {
    ".py", ".js", ".ts", ".env", ".yaml", ".yml",
    ".json", ".sh", ".bash", ".tf", ".toml", ".ini",
    ".cfg", ".conf", ".properties", ".xml", ".php",
    ".rb", ".go", ".java", ".cs", ".txt", ".md"
}

IGNORE_PATHS = {
    ".git", "node_modules", "__pycache__", ".venv",
    "venv", "dist", "build", ".pytest_cache",
    "package-lock.json", "yarn.lock", "poetry.lock",
}


class SecretsScanner(BaseScanner):
    name = "Secrets Scanner"

    def scan(self) -> list[dict]:
        findings = []
        for filepath in self._get_files():
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                findings.extend(self._scan_file(filepath, content))
            except (PermissionError, IsADirectoryError):
                continue
        return findings

    def _get_files(self):
        for path in self.repo_path.rglob("*"):
            if any(part in IGNORE_PATHS for part in path.parts):
                continue
            if path.is_file() and path.suffix in INCLUDE_EXTENSIONS:
                yield path
            elif path.is_file() and path.name.startswith(".env"):
                yield path

    def _scan_file(self, filepath: Path, content: str) -> list[dict]:
        findings = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for secret_name, pattern, severity in SECRET_PATTERNS:
                if re.search(pattern, line):
                    masked_line = re.sub(
                        r"(['\"])[^'\"]{4}([^'\"]+)['\"]",
                        r"\1****\2****\1",
                        line.strip()
                    )
                    findings.append(self._make_finding(
                        title=f"Segredo hardcoded: {secret_name}",
                        severity=severity,
                        file=f"{filepath.relative_to(self.repo_path)}:{line_num}",
                        detail=f"Possível {secret_name} detectado → {masked_line[:120]}",
                        remediation=(
                            "Remove o valor do código. Usa variáveis de ambiente "
                            "(os.environ) ou um gestor de segredos como Azure Key Vault."
                        )
                    ))
                    break
        return findings