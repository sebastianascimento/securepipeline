"""
KeyVaultScanner
Verifica se o projeto está a usar Azure Key Vault
em vez de segredos hardcoded — e deteta padrões
que deviam estar no Key Vault.
"""

import re
from pathlib import Path
from .base_scanner import BaseScanner


# Padrões que indicam que o código NÃO está a usar Key Vault
# quando devia estar
BAD_PATTERNS = [
    (
        "Segredo devia estar no Key Vault",
        r"(?i)(os\.environ\.get|os\.getenv)\(['\"]"
        r"(password|secret|key|token|api_key)['\"]"
        r"\s*,\s*['\"][^'\"]{4,}['\"]",
        "MEDIUM",
        "O valor default hardcoded devia vir do Key Vault, não do código."
    ),
    (
        "Conexão ao Key Vault não encontrada",
        None,  # verificação especial — ver abaixo
        "LOW",
        "Considera usar Azure Key Vault para gerir segredos."
    ),
]

KEYVAULT_INDICATORS = [
    "azure.keyvault",
    "SecretClient",
    "KeyVaultSecret",
    "vault.azure.net",
    "DefaultAzureCredential",
]

INCLUDE_EXTENSIONS = {".py", ".js", ".ts", ".env", ".yaml", ".yml"}
IGNORE_PATHS = {".git", "node_modules", "__pycache__", "venv", ".venv"}


class KeyVaultScanner(BaseScanner):
    name = "Key Vault Scanner"

    def scan(self) -> list[dict]:
        findings = []
        all_content = ""

        for filepath in self._get_files():
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                all_content += content
                findings.extend(self._scan_file(filepath, content))
            except (PermissionError, IsADirectoryError):
                continue

        # Verifica se o projeto usa Key Vault em algum sítio
        uses_keyvault = any(
            indicator in all_content
            for indicator in KEYVAULT_INDICATORS
        )

        if not uses_keyvault and self._has_secrets_usage(all_content):
            findings.append(self._make_finding(
                title="Projeto não usa Azure Key Vault",
                severity="LOW",
                file="N/A",
                detail=(
                    "O projeto usa variáveis de ambiente para segredos "
                    "mas não integra Azure Key Vault."
                ),
                remediation=(
                    "Integra o SDK do Azure Key Vault: "
                    "'pip install azure-keyvault-secrets azure-identity'. "
                    "Usa SecretClient para buscar segredos em runtime."
                )
            ))

        return findings

    def _get_files(self):
        for path in self.repo_path.rglob("*"):
            if any(part in IGNORE_PATHS for part in path.parts):
                continue
            if path.is_file() and path.suffix in INCLUDE_EXTENSIONS:
                yield path

    def _scan_file(self, filepath: Path, content: str) -> list[dict]:
        findings = []
        rel = filepath.relative_to(self.repo_path)

        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Deteta os.environ.get com valor default hardcoded
            if re.search(BAD_PATTERNS[0][1], line):
                findings.append(self._make_finding(
                    title=BAD_PATTERNS[0][0],
                    severity=BAD_PATTERNS[0][2],
                    file=f"{rel}:{line_num}",
                    detail=f"'{stripped[:80]}' tem valor default hardcoded.",
                    remediation=BAD_PATTERNS[0][3]
                ))

        return findings

    def _has_secrets_usage(self, content: str) -> bool:
        """Verifica se o código usa variáveis de ambiente para segredos."""
        return bool(re.search(
            r"(?i)os\.(environ|getenv).*?(password|secret|key|token)",
            content
        ))