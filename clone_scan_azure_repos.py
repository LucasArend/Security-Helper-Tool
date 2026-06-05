import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import os
import re

def escolher_pasta():
    pasta = filedialog.askdirectory()
    if pasta:
        pasta_var.set(pasta)

def run_trivy(repo_path, report_path):
    subprocess.run([
        "trivy", "fs",
        "--quiet",
        "--format", "json",
        "--output", os.path.join(report_path, "trivy.json"),
        repo_path
    ])

def run_semgrep(repo_path, report_path):
    subprocess.run([
        "semgrep",
        "--config", "auto",
        "--json",
        "--output", os.path.join(report_path, "semgrep.json"),
        repo_path
    ])

def clone_and_scan():
    project_url = url_entry.get().strip()
    destino = pasta_var.get().strip()

    if not project_url or not destino:
        messagebox.showerror("Erro", "Informe o link e a pasta de destino.")
        return

    match = re.match(r"https://dev.azure.com/([^/]+)/([^/]+)", project_url)
    if not match:
        messagebox.showerror("Erro", "URL inválida.")
        return

    org, project = match.groups()

    try:
        subprocess.run(
            ["az", "devops", "configure", "--defaults",
             f"organization=https://dev.azure.com/{org}", f"project={project}"],
            check=True
        )

        repos = subprocess.check_output(
            ["az", "repos", "list", "--query", "[].name", "-o", "tsv"],
            text=True
        ).splitlines()

        reports_root = os.path.join(destino, "reports")
        os.makedirs(reports_root, exist_ok=True)

        for repo in repos:
            repo_path = os.path.join(destino, repo)
            report_path = os.path.join(reports_root, repo)
            os.makedirs(report_path, exist_ok=True)

            if not os.path.exists(repo_path):
                subprocess.run([
                    "git", "clone",
                    f"https://dev.azure.com/{org}/{project}/_git/{repo}",
                    repo_path
                ])

            run_trivy(repo_path, report_path)
            run_semgrep(repo_path, report_path)

        messagebox.showinfo("Sucesso", "Clone e análise concluídos!")

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Erro", str(e))

# GUI
root = tk.Tk()
root.title("Azure DevOps – Clone + Trivy + Semgrep")
root.geometry("650x220")

tk.Label(root, text="Link do projeto Azure DevOps:").pack(pady=5)
url_entry = tk.Entry(root, width=90)
url_entry.pack()

tk.Label(root, text="Pasta de destino:").pack(pady=5)

frame = tk.Frame(root)
frame.pack()

pasta_var = tk.StringVar()
tk.Entry(frame, width=60, textvariable=pasta_var).pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Escolher pasta", command=escolher_pasta).pack(side=tk.LEFT)

tk.Button(root, text="Clonar e escanear", command=clone_and_scan).pack(pady=15)

root.mainloop()