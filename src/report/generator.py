"""
ReportGenerator
Gera um relatório PDF profissional a partir dos findings
usando Jinja2 para o template HTML e WeasyPrint para o PDF.
"""

from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML


class ReportGenerator:

    def __init__(self):
        templates_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(templates_dir)))

    def generate(self, results: dict, output_path: str) -> str:
        """
        Gera o PDF e guarda em output_path.
        Devolve o caminho do ficheiro gerado.
        """
        template = self.env.get_template("report.html")

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            results["findings"],
            key=lambda f: severity_order.get(f["severity"], 4)
        )

        html_content = template.render(
            repo=Path(results["repo"]).name,
            date=datetime.now().strftime("%d %B %Y"),
            total=len(results["findings"]),
            summary=results["summary"],
            findings=sorted_findings
        )

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html_content).write_pdf(str(output))

        return str(output)