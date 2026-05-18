from abc import ABC, abstractmethod
from pathlib import Path


class BaseScanner(ABC):
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def scan(self) -> list[dict]:
        """
        Cada finding tem:
            - title, severity, file, detail, remediation
        """
        pass

    def _make_finding(self, title, severity, file, detail, remediation) -> dict:
        return {
            "title": title,
            "severity": severity,
            "file": str(file),
            "detail": detail,
            "remediation": remediation,
        }