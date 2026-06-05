import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os

from services.azure_clone_service import clone_all_repositories
from services.scan_service import scan_repositories, concatenate_reports
# Certifique-se de que a sua service consiga renderizar passando o template alternativo e o json bruto
from services.report_service import generate_html_report 


class SecurityToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Helper Tool")
        self.root.geometry("450x380")  # Aumentado ligeiramente a altura para acomodar o novo botão
        self.root.resizable(False, False)

        self.cancel_clone_event = threading.Event()
        self.cancel_scan_event = threading.Event()

        self.setup_styles()
        self.build_ui()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        COLOR_BG = "#f8fafc"        
        self.COLOR_PRIMARY = "#1e293b"   
        COLOR_HOVER = "#334155"     
        COLOR_ACCENT = "#0284c7"    
        self.COLOR_CANCEL = "#b43f3f"  
        self.COLOR_CANCEL_HOVER = "#bd2525"

        self.root.configure(background=COLOR_BG)

        self.style.configure("TLabel", background=COLOR_BG, foreground="#0f172a", font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=self.COLOR_PRIMARY)
        self.style.configure("Sub.TLabel", font=("Segoe UI", 9, "italic"), foreground="#64748b")

        self.style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            background=self.COLOR_PRIMARY,
            foreground="white",
            borderwidth=0,
            focalthickness=0,
            padding=8
        )
        self.style.map("TButton", background=[("active", COLOR_HOVER)])

        self.style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 9, "bold"),
            background="#e2e8f0",
            foreground="#334155",
            padding=5
        )
        self.style.map("Secondary.TButton", background=[("active", "#cbd5e1")])

        self.style.configure(
            "Cancel.TButton",
            font=("Segoe UI", 10, "bold"),
            background=self.COLOR_CANCEL,
            foreground="white",
            padding=8
        )
        self.style.map("Cancel.TButton", background=[("active", self.COLOR_CANCEL_HOVER)])

        # Estilo customizado para o botão de Triagem se destacar discretamente
        self.style.configure(
            "Triage.TButton",
            font=("Segoe UI", 10, "bold"),
            background="#0284c7",
            foreground="white",
            padding=8
        )
        self.style.map("Triage.TButton", background=[("active", "#0369a1")])

        self.style.configure("TFrame", background=COLOR_BG)
        self.style.configure("TEntry", fieldbackground="white", borderwidth=1, font=("Segoe UI", 10))
        self.style.configure("TRadiobutton", background=COLOR_BG, foreground="#334155", font=("Segoe UI", 10))
        self.style.configure("TProgressbar", thickness=12, troughcolor="#e2e8f0", background=COLOR_ACCENT)

    def build_ui(self):
        main_frame = ttk.Frame(self.root, padding=25)
        main_frame.pack(fill="both", expand=True)

        ttk.Label(main_frame, text="Security Helper Tool", style="Header.TLabel").pack(pady=(0, 5))
        ttk.Label(main_frame, text="Central de Análise de Vulnerabilidades", style="Sub.TLabel").pack(pady=(0, 25))

        ttk.Button(main_frame, text="Clone Azure Repositories", command=self.open_clone_window).pack(fill="x", pady=6)
        ttk.Button(main_frame, text="Vulnerability Scan Manager", command=self.open_scan_window).pack(fill="x", pady=6)
        
        # NOVO BOTÃO DE TRIAGEM
        ttk.Button(main_frame, text="Triage & Edit SARIF Report", command=self.generate_edit_report).pack(fill="x", pady=12)

    #  CLONE 

    def open_clone_window(self):
        self.clone_window = tk.Toplevel(self.root)
        self.clone_window.title("Clone Azure Repositories")
        self.clone_window.geometry("580x360")
        self.clone_window.configure(background="#f8fafc")

        frame = ttk.Frame(self.clone_window, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Repository URL:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))
        self.repo_entry = ttk.Entry(frame)
        self.repo_entry.pack(fill="x", pady=(0, 15))

        ttk.Label(frame, text="Destination Folder:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        folder_frame = ttk.Frame(frame)
        folder_frame.pack(fill="x", pady=(0, 20))

        self.dest_entry = ttk.Entry(folder_frame)
        self.dest_entry.pack(side="left", fill="x", expand=True, ipady=3)

        ttk.Button(folder_frame, text="Browse...", style="Secondary.TButton", command=self.choose_directory).pack(side="left", padx=(8, 0))

        self.clone_status = ttk.Label(frame, text="Aguardando início...", style="Sub.TLabel")
        self.clone_status.pack(anchor="w")

        self.clone_progress = ttk.Progressbar(frame, mode="determinate")
        self.clone_progress.pack(fill="x", pady=(5, 20))

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x")
        
        self.clone_btn = ttk.Button(btn_frame, text="Start Mirroring Clone", command=self.start_clone)
        self.clone_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self.cancel_clone_btn = ttk.Button(btn_frame, text="Cancelar", style="Cancel.TButton", command=self.cancel_clone, state="disabled")
        self.cancel_clone_btn.pack(side="left", fill="x", expand=True, padx=(4, 0))

    def choose_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, directory)

    def cancel_clone(self):
        self.cancel_clone_event.set()
        self.clone_status.config(text="Cancelando operação...")
        self.cancel_clone_btn.config(state="disabled")

    def start_clone(self):
        repo_url = self.repo_entry.get().strip()
        destination = self.dest_entry.get().strip()

        if not repo_url or not destination:
            messagebox.showwarning("Atenção", "Preencha a URL e a pasta de destino.")
            return

        self.cancel_clone_event.clear() 
        self.clone_progress["value"] = 0
        self.clone_status.config(text="Iniciando conexões...")
        self.clone_btn.config(state="disabled")
        self.cancel_clone_btn.config(state="normal")

        def progress_callback(current, total, repo_name):
            def update():
                if total > 0:
                    self.clone_progress["maximum"] = total
                    self.clone_progress["value"] = current
                self.clone_status.config(
                    text=f"Clonando ({current}/{total}): {repo_name}" if total > 0 else repo_name
                )
            self.root.after(0, update)

        def run():
            results = clone_all_repositories(repo_url, destination, progress_callback, self.cancel_clone_event)

            failed = [(name, msg) for name, ok, msg in results if not ok and name != "error"]
            errors = [(name, msg) for name, ok, msg in results if not ok and name == "error"]

            def finish():
                self.clone_btn.config(state="normal")
                self.cancel_clone_btn.config(state="disabled")
                
                if self.cancel_clone_event.is_set():
                    self.clone_status.config(text="Operação cancelada pelo usuário.")
                    messagebox.showwarning("Cancelado", "O processo de clonagem foi interrompido.")
                elif errors:
                    messagebox.showerror("Erro", errors[0][1])
                elif failed:
                    msgs = "\n".join(f"• {name}: {msg}" for name, msg in failed)
                    messagebox.showwarning("Falhas no clone", f"Os seguintes repositórios falharam:\n\n{msgs}")
                else:
                    messagebox.showinfo("Concluído", "Todos os repositórios foram clonados com sucesso!")

            self.root.after(0, finish)

        threading.Thread(target=run, daemon=True).start()

    #  SCAN 

    def open_scan_window(self):
        self.scan_window = tk.Toplevel(self.root)
        self.scan_window.title("Scan Repositories")
        self.scan_window.geometry("600x480")
        self.scan_window.configure(background="#f8fafc")

        frame = ttk.Frame(self.scan_window, padding=20)
        frame.pack(fill="both", expand=True)

        self.scan_type = tk.StringVar(value="trivy")

        ttk.Label(frame, text="Select Scan Type:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        radio_frame = ttk.Frame(frame)
        radio_frame.pack(anchor="w", pady=(0, 15))
        
        for label, value in [("Trivy (SCA)", "trivy"), ("Semgrep (SAST)", "semgrep"), ("Trivy + Semgrep", "both")]:
            ttk.Radiobutton(radio_frame, text=label, variable=self.scan_type, value=value).pack(side="left", padx=(0, 15))

        ttk.Label(frame, text="Base Repositories Folder:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 4))

        folder_frame = ttk.Frame(frame)
        folder_frame.pack(fill="x", pady=(0, 15))

        self.scan_path_entry = ttk.Entry(folder_frame)
        self.scan_path_entry.pack(side="left", fill="x", expand=True, ipady=3)

        ttk.Button(folder_frame, text="Browse...", style="Secondary.TButton", command=self.choose_scan_directory).pack(side="left", padx=(8, 0))

        self.scan_status = ttk.Label(frame, text="Pronto para escanear.", style="Sub.TLabel")
        self.scan_status.pack(anchor="w")

        self.scan_progress = ttk.Progressbar(frame, mode="determinate")
        self.scan_progress.pack(fill="x", pady=(5, 20))

        separator = ttk.Separator(frame, orient="horizontal")
        separator.pack(fill="x", pady=(0, 20))

        scan_action_frame = ttk.Frame(frame)
        scan_action_frame.pack(fill="x", pady=4)
        
        self.scan_btn = ttk.Button(scan_action_frame, text="Run Security Engine Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self.cancel_scan_btn = ttk.Button(scan_action_frame, text="Cancelar Scan", style="Cancel.TButton", command=self.cancel_scan, state="disabled")
        self.cancel_scan_btn.pack(side="left", fill="x", expand=True, padx=(4, 0))
        
        actions_frame = ttk.Frame(frame)
        actions_frame.pack(fill="x", pady=8)
        
        ttk.Button(actions_frame, text="Concat JSONs", command=self.concat_reports).pack(fill="x", pady=15)
        ttk.Button(actions_frame, text="Build HTML Dashboard", command=self.generate_report).pack(fill="x", pady=8)

    def choose_scan_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.scan_path_entry.delete(0, tk.END)
            self.scan_path_entry.insert(0, directory)

    def cancel_scan(self):
        self.cancel_scan_event.set()
        self.scan_status.config(text="Cancelando varredura...")
        self.cancel_scan_btn.config(state="disabled")

    def start_scan(self):
        base_path = self.scan_path_entry.get().strip()
        if not base_path:
            messagebox.showwarning("Atenção", "Selecione a pasta base dos repositórios.")
            return

        self.cancel_scan_event.clear()
        self.scan_btn.config(state="disabled")
        self.cancel_scan_btn.config(state="normal")
        self.scan_progress["value"] = 0
        self.scan_status.config(text="Inicializando varredura...")

        def progress_callback(current, total, repo_name):
            def update():
                self.scan_progress["maximum"] = max(total, 1)
                self.scan_progress["value"] = current
                self.scan_status.config(text=f"Analisando ({current}/{total}): {repo_name}")
            self.root.after(0, update)

        def run():
            scan_repositories(base_path, self.scan_type.get(), progress_callback, self.cancel_scan_event)

            def finish():
                self.scan_btn.config(state="normal")
                self.cancel_scan_btn.config(state="disabled")
                
                if self.cancel_scan_event.is_set():
                    self.scan_status.config(text="Varredura interrompida pelo usuário.")
                    messagebox.showwarning("Cancelado", "O escaneamento foi interrompido.")
                else:
                    self.scan_status.config(text="Varredura completa.")
                    messagebox.showinfo("Scan concluído", "Scan finalizado com sucesso!")

            self.root.after(0, finish)

        threading.Thread(target=run, daemon=True).start()

    def concat_reports(self):
        base_path = self.scan_path_entry.get().strip()
        if not base_path:
            messagebox.showwarning("Atenção", "Selecione a pasta base dos repositórios.")
            return
        try:
            output = concatenate_reports(base_path)
            messagebox.showinfo("Relatório gerado", f"Relatório final criado:\n{output}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    def generate_report(self):
        json_path = filedialog.askopenfilename(
            title="Selecione o relatório JSON para converter em HTML",
            filetypes=[("Arquivos JSON/SARIF", "*.json *.sarif"), ("Todos os arquivos", "*.*")]
        )
        if not json_path:
            return

        try:
            html = generate_html_report(json_path)
            messagebox.showinfo("HTML Report", f"Relatório HTML gerado com sucesso em:\n{html}")
        except Exception as e:
            messagebox.showerror("Erro ao gerar relatório", str(e))

    # NOVO MÉTODO PARA GERAR O TEMPLATE DE TRIAGEM (EDIÇÃO)
    def generate_edit_report(self):
        json_path = filedialog.askopenfilename(
            title="Selecione o arquivo SARIF para Triagem/Edição",
            filetypes=[("Arquivos JSON/SARIF", "*.json *.sarif"), ("Todos os arquivos", "*.*")]
        )
        if not json_path:
            return

        try:
            # Passamos o parâmetro do template customizado de triagem que está em /templates
            # Certifique-se de que sua função 'generate_html_report' aceite receber o nome do template por parâmetro
            html = generate_html_report(json_path, template_name="report_template_edit.html")
            messagebox.showinfo("Modo Triagem", f"Painel de Triagem gerado com sucesso!\n\nAbra o arquivo no seu navegador para editar:\n{html}")
        except Exception as e:
            messagebox.showerror("Erro ao gerar painel de triagem", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolApp(root)
    root.mainloop()