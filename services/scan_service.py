import os
import json
import subprocess
import re

IGNORE_REPO_REGEX = [
    r"authorization-policy-allow\.yaml",
]

def is_ignored_repo(path: str) -> bool:
    return any(re.search(rx, path, re.IGNORECASE) for rx in IGNORE_REPO_REGEX)


# REPOS

def is_git_repository(path):
    return os.path.isdir(os.path.join(path, ".git"))


def find_repositories(base_path):
    repos = []

    if not os.path.isdir(base_path):
        return repos

    for item in os.listdir(base_path):
        full_path = os.path.join(base_path, item)

        if not os.path.isdir(full_path):
            continue

        if is_ignored_repo(full_path):
            continue

        if is_git_repository(full_path):
            repos.append(full_path)

    return sorted(repos)


# SCANS

def run_trivy(repo_path):
    # Alterado para salvar como .sarif para fazer mais sentido semântico
    report_path = os.path.join(repo_path, "trivy_report.sarif")
    command = [
        "trivy", "fs",
        repo_path,
        "--scanners", "vuln,misconfig,secret",
        "--skip-dirs", "node_modules,dist,build,.next,coverage,.turbo,.nx",
        "--format", "sarif",  # 👈 MODIFICADO: De 'json' para 'sarif'
        "--quiet",
        "-o", report_path
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Erro ao executar Trivy em {repo_path}:\n{result.stderr}"
        )

    return report_path


def run_semgrep(repo_path):
    # Alterado para salvar como .sarif
    report_path = os.path.join(repo_path, "semgrep_report.sarif")

    configs = [
        "p/default", "p/owasp-top-ten", "p/security-audit", "p/javascript",
        "p/typescript", "p/nodejs", "p/react", "p/nextjs", "p/nestjs",
        "p/docker", "p/dockerfile", "p/secrets", "p/ci",
    ]

    excludes = [
        "node_modules", "dist", "build", ".next", "coverage", ".turbo", ".nx",
        "*.min.js", "package-lock.json", "*.test.ts", "*.test.tsx", "*.test.js",
        "*.spec.ts", "*.spec.tsx", "*.spec.js", "__tests__", "__mocks__",
        "test", "tests", "e2e", "mocks", "fixtures", "*.stories.ts", "*.stories.tsx",
        ".storybook",
    ]

    command = [
        "semgrep", "scan",
        "--sarif",  # 👈 MODIFICADO: De '--json' para '--sarif'
        "--output", report_path,
        "--metrics=off",
        "--disable-version-check",
    ]

    for config in configs:
        command.extend(["--config", config])

    for exclude in excludes:
        command.extend(["--exclude", exclude])

    command.append(repo_path)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Erro ao executar Semgrep em {repo_path}:\n{result.stderr}"
        )

    return report_path


def scan_repositories(base_path, scan_type, progress_callback=None, cancel_event=None):
    repos = find_repositories(base_path)
    total = len(repos)
    generated_reports = []

    if total == 0:
        if progress_callback:
            progress_callback(0, 1, "Nenhum repositório encontrado.")
        return generated_reports

    for index, repo in enumerate(repos, start=1):
        if cancel_event and cancel_event.is_set():
            break

        repo_name = os.path.basename(repo)

        if progress_callback:
            progress_callback(index - 1, total, repo_name)

        if scan_type in ("trivy", "both"):
            generated_reports.append(run_trivy(repo))

        if cancel_event and cancel_event.is_set():
            break

        if scan_type in ("semgrep", "both"):
            generated_reports.append(run_semgrep(repo))

    if cancel_event and cancel_event.is_set():
        if progress_callback:
            progress_callback(index - 1, total, "Varredura cancelada.")
        return generated_reports

    if progress_callback:
        progress_callback(total, total, "Concluído!")

    return generated_reports


# CONCATENAÇÃO (MODIFICADA PARA PADRÃO SARIF)

def concatenate_reports(base_path, output_file="final_report.sarif"):
    output_path = os.path.join(base_path, output_file)
    
    # Estrutura base padrão exigida pela especificação SARIF v2.1.0
    sarif_master = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": []
    }

    for root, _, files in os.walk(base_path):
        for file in sorted(files):
            # Passa a buscar tanto arquivos antigos .json quanto os novos .sarif
            if not (file.endswith("_report.json") or file.endswith("_report.sarif")):
                continue

            report_file = os.path.join(root, file)

            if os.path.abspath(report_file) == os.path.abspath(output_path):
                continue

            if is_ignored_repo(report_file):
                continue

            try:
                with open(report_file, "r", encoding="utf-8") as infile:
                    content = infile.read().strip()

                if not content:
                    continue

                data = json.loads(content)

                # Verifica se o arquivo lido possui a estrutura SARIF válida ("runs")
                if "runs" in data and isinstance(data["runs"], list):
                    for run in data["runs"]:
                        # Metadado opcional: Injeta o caminho relativo para você saber de qual repositório/arquivo veio
                        if "automationDetails" not in run:
                            run["automationDetails"] = {}
                        run["automationDetails"]["id"] = os.path.relpath(report_file, base_path)
                        
                        # Adiciona a execução da ferramenta na lista global
                        sarif_master["runs"].append(run)

            except (json.JSONDecodeError, OSError):
                continue

    # Escreve o arquivo unificado no formato SARIF estrito
    with open(output_path, "w", encoding="utf-8") as outfile:
        json.dump(
            sarif_master,
            outfile,
            indent=2,
            ensure_ascii=False
        )

    return output_path