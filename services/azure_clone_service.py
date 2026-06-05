import os
import subprocess
import requests
from base64 import b64encode
from urllib.parse import quote, urlparse, urlunparse


def get_repositories(org, project):
    pat = os.getenv("AZURE_DEVOPS_PAT")
    if not pat:
        raise Exception("AZURE_DEVOPS_PAT não configurado. Defina a variável de ambiente AZURE_DEVOPS_PAT.")

    auth = b64encode(f":{pat}".encode()).decode()
    url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version=7.0"

    response = requests.get(
        url,
        headers={"Authorization": f"Basic {auth}"}
    )
    response.raise_for_status()
    return response.json()["value"]


def get_authenticated_repo_url(repo_url, pat):
    parsed = urlparse(repo_url)
    if parsed.scheme not in ("http", "https"):
        return repo_url

    hostname = parsed.hostname
    if not hostname:
        return repo_url

    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"

    auth_netloc = f"user:{quote(pat)}@{netloc}"
    return urlunparse(parsed._replace(netloc=auth_netloc))


def clone_all_repositories(base_repo_url, destination, progress_callback=None, cancel_event=None):
    """
    Recebe qualquer URL de repo do projeto e clona TODOS os repositórios.
    Exemplo de URL: https://dev.azure.com/org/project/_git/repo
    """
    try:
        pat = os.getenv("AZURE_DEVOPS_PAT")
        if not pat:
            raise Exception("AZURE_DEVOPS_PAT não configurado. Defina a variável de ambiente AZURE_DEVOPS_PAT.")

        parts = base_repo_url.rstrip("/").split("/")
        if len(parts) < 5:
            raise Exception("URL inválida. Use o formato: https://dev.azure.com/org/project/_git/repo")

        org = parts[3]
        project = parts[4]

        if progress_callback:
            progress_callback(0, 0, "Buscando repositórios...")

        repos = get_repositories(org, project)
        total = len(repos)

        if cancel_event and cancel_event.is_set():
            return results if 'results' in locals() else []

        if total == 0:
            if progress_callback:
                progress_callback(0, 1, "Nenhum repositório encontrado.")
            return []

        results = []

        for index, repo in enumerate(repos, start=1):
            if cancel_event and cancel_event.is_set():
                break

            repo_name = repo["name"]
            repo_url = repo["remoteUrl"]
            target_path = os.path.join(destination, repo_name)

            if progress_callback:
                progress_callback(index - 1, total, repo_name)

            if os.path.isdir(target_path):
                results.append((repo_name, True, "Já existe, pulado."))
                continue

            auth_repo_url = get_authenticated_repo_url(repo_url, pat)
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"

            result = subprocess.run(
                ["git", "clone", auth_repo_url, target_path],
                capture_output=True,
                text=True,
                env=env
            )

            if result.returncode == 0:
                results.append((repo_name, True, "OK"))
            else:
                results.append((repo_name, False, result.stderr.strip()))

        if cancel_event and cancel_event.is_set():
            if progress_callback:
                progress_callback(index - 1, total, "Clonagem cancelada.")
            return results

        if progress_callback:
            progress_callback(total, total, "Concluído!")

        return results

    except requests.HTTPError as e:
        msg = f"Erro HTTP ao buscar repositórios: {e.response.status_code} - {e.response.text}"
        if progress_callback:
            progress_callback(0, 0, msg)
        return [("error", False, msg)]

    except Exception as e:
        msg = str(e)
        if progress_callback:
            progress_callback(0, 0, f"Erro: {msg}")
        return [("error", False, msg)]