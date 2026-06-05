import json
import base64
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "WARNING": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

def normalize_severity(raw):
    raw = str(raw or "").upper()
    return {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "ERROR": "HIGH",
        "MEDIUM": "MEDIUM",
        "WARNING": "MEDIUM",
        "LOW": "LOW",
        "INFO": "LOW",
    }.get(raw, "UNKNOWN")

def extract_rules_map(run_item):
    """ Mapeia as regras (rules) definidas na ferramenta para busca rápida """
    rules_map = {}
    driver = run_item.get("tool", {}).get("driver", {})
    for rule in driver.get("rules", []):
        rule_id = rule.get("id")
        if rule_id:
            rules_map[rule_id] = rule
    return rules_map

def get_rule_severity(rule, result):
    """ Extrai a severidade da regra ou do resultado do SARIF """
    # Tenta pegar das tags customizadas do Trivy/Semgrep
    properties = rule.get("properties", {})
    tags = properties.get("tags", [])
    for tag in tags:
        if tag.upper() in SEVERITY_ORDER:
            return tag.upper()
    
    # Fallback para o nível padrão do SARIF (error, warning, note)
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
    if level == "error":
        return "HIGH"
    elif level == "note":
        return "LOW"
    return "MEDIUM"

# MAIN
def generate_html_report(json_path, template_name="report_template.html"):
    if not os.path.isfile(json_path):
        raise FileNotFoundError(f"Arquivo JSON/SARIF não encontrado em: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    # Garante que o JSON bruto vire uma string segura em linha única, 
    # escapando aspas e caracteres especiais perigosos para o JavaScript.
    json_string_limpa = json.dumps(data)
    json_base64 = base64.b64encode(json_string_limpa.encode('utf-8')).decode('utf-8')

    base_dir = os.path.dirname(json_path)
    
    # Altera o nome do HTML de saída baseado no template escolhido
    if "edit" in template_name:
        output_path = os.path.join(base_dir, "relatorio_scan_edit.html")
    else:
        output_path = os.path.join(base_dir, "relatorio_scan.html")

    global_counters = {k: 0 for k in SEVERITY_ORDER}
    processed_repositories = []

    # No SARIF, tudo gira em torno da lista de execuções ("runs")
    runs_list = data.get("runs", []) if isinstance(data, dict) else []

    for run_idx, run in enumerate(runs_list):
        if not isinstance(run, dict):
            continue

        tool_name = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
        
        # Recupera o caminho do repositório que injetamos na concatenação
        repo_path = run.get("automationDetails", {}).get("id", f"Repositório #{run_idx + 1}")
        repo_name = os.path.dirname(repo_path) if "/" in repo_path else repo_path
        if not repo_name or repo_name == ".":
            repo_name = "Raiz"

        display_name = f"{repo_name} (Scan: {tool_name})"
        
        repo_findings = []
        repo_counters = {k: 0 for k in SEVERITY_ORDER}
        
        # Map das regras para enriquecer os achados (results)
        rules_map = extract_rules_map(run)

        # 1. PROCESSAR ERROS OPERACIONAIS (Invocations / Notifications)
        for invocation in run.get("invocations", []):
            for notification in invocation.get("toolExecutionNotifications", []):
                severity = "WARNING"
                repo_counters[severity] += 1
                global_counters[severity] += 1

                msg_text = notification.get("message", {}).get("text", "Erro interno da ferramenta")
                descriptor_id = notification.get("descriptor", {}).get("id", "Erro Operacional")

                repo_findings.append({
                    "tool": tool_name,
                    "severity": severity,
                    "target": "Erro Operacional / Sistema",
                    "title": f"Falha na execução: {descriptor_id}",
                    "description": msg_text,
                    "fix_suggestion": "Verifique os logs ou a sintaxe do arquivo afetado.",
                    "run_index": run_idx,
                    "result_index": -1 # Notificações não têm índice em 'results'
                })

        # 2. PROCESSAR VULNERABILIDADES REAIS (Results)
        results = run.get("results", [])
        for res_idx, result in enumerate(results):
            rule_id = result.get("ruleId")
            rule = rules_map.get(rule_id, {})

            # Determina a severidade cruzando regra + resultado
            severity = normalize_severity(get_rule_severity(rule, result))
            
            # Semgrep High Confidence -> Critical (mantendo sua regra antiga)
            if tool_name == "Semgrep OSS" and severity == "HIGH":
                if "HIGH CONFIDENCE" in [t.upper() for t in rule.get("properties", {}).get("tags", [])]:
                    severity = "CRITICAL"

            repo_counters[severity] += 1
            global_counters[severity] += 1

            # Extrai localização (Arquivo e Linha)
            target_file = "Arquivo não especificado"
            start_line = "?"
            locations = result.get("locations", [])
            if locations:
                phys_loc = locations[0].get("physicalLocation", {})
                artifact_loc = phys_loc.get("artifactLocation", {})
                target_file = artifact_loc.get("uri", "Arquivo desconhecido")
                start_line = phys_loc.get("region", {}).get("startLine", "?")

            # Monta textos baseados no dicionário de regras do SARIF
            title = rule.get("shortDescription", {}).get("text", rule_id)
            
            # PRIORIDADE DE DESCRIÇÃO: 
            # 1. Buscamos a descrição longa e detalhada da vulnerabilidade na Regra (fullDescription)
            description = rule.get("fullDescription", {}).get("text", "")
            
            # 2. Caso a ferramenta não tenha preenchido fullDescription, tentamos o shortDescription
            if not description:
                description = rule.get("shortDescription", {}).get("text", "")
                
            # 3. Fallback: Se ainda estiver vazio ou for o Semgrep padrão, tenta extrair do text/markdown
            if not description or len(description) < 10:
                description = result.get("message", {}).get("text", "Descrição não disponível no log original.")

            # Se a ferramenta for o Trivy e veio aquele bloco com "Vulnerability CVE-...", 
            # podemos limpar e extrair apenas o texto corrido (estilo o do protobufjs) se ele existir no help
            if tool_name == "Trivy" and "Vulnerability CVE-" in description:
                # Caso o fullDescription não estivesse preenchido e caímos no help formatado,
                # tentamos isolar o parágrafo que descreve a vulnerabilidade
                help_text = rule.get("help", {}).get("text", "")
                if help_text and "\nLink: " in help_text:
                    # O texto oficial da vulnerabilidade geralmente começa após o padrão de links do Trivy
                    partes = help_text.split(")\n")
                    if len(partes) > 1:
                        description = partes[-1].strip()
            # Se mesmo assim falhar, define um fallback
            if not description:
                description = "Descrição não disponível no log original."
            
            # Para o Trivy, tenta achar o nome do pacote nas propriedades ou help
            pkg_name = target_file
            if tool_name == "Trivy":
                help_text = rule.get("help", {}).get("text", "")
                for line in help_text.split("\n"):
                    if line.startswith("Package:"):
                        pkg_name = line.replace("Package:", "").strip()
                        break

            # Sugestão de correção (Pega do helpUri ou referências)
            fix_suggestion = rule.get("helpUri", "N/A")

            if tool_name == "Trivy":
                help_text = rule.get("help", {}).get("text", "")
                fixed_version = "versão segura"
                
                for line in help_text.split("\n"):
                    if "Fixed Version:" in line:
                        fixed_version = line.replace("Fixed Version:", "").strip()
                        break
                        
                if fixed_version and fixed_version != "versão segura":
                    fix_suggestion = f"Atualize para a versão {fixed_version}."
                else:
                    fix_suggestion = f"Consulte o link para mitigação: {rule.get('helpUri', 'N/A')}"
                    
            elif tool_name == "Semgrep OSS":
                fix_suggestion = rule.get("helpUri", "N/A")

            repo_findings.append({
                "tool": tool_name,
                "severity": severity,
                "target": f"{pkg_name} : Linha {start_line}" if tool_name != "Trivy" else f"{pkg_name}",
                "title": f"{rule_id} - {title}" if tool_name == "Trivy" else title,
                "description": description,
                "fix_suggestion": fix_suggestion,
                "run_index": run_idx,       # Injetado dinamicamente para o JS mapear no DOM
                "result_index": res_idx     # Injetado dinamicamente para o JS mapear no DOM
            })

        # 3. AGRUPAMENTO POR COMPONENTE
        if repo_findings:
            grouped = {}
            for f in repo_findings:
                # Trata o nome do pacote para agrupamento limpo
                pkg_base = f["target"].split(" : Linha")[0].split(" (")[0].strip()
                group_key = f"{f['tool']}::{pkg_base}"

                if group_key not in grouped:
                    grouped[group_key] = {
                        "target_name": pkg_base,
                        "versions": set(),
                        "highest_severity": f["severity"],
                        "vulnerabilities": [],
                    }

                version_match = f["target"].split("(v")
                if len(version_match) > 1:
                    version = version_match[1].rstrip(")")
                    grouped[group_key]["versions"].add(version)

                if SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER[grouped[group_key]["highest_severity"]]:
                    grouped[group_key]["highest_severity"] = f["severity"]

                grouped[group_key]["vulnerabilities"].append(f)

            findings_list = []
            for g in grouped.values():
                if g["versions"]:
                    versions_str = ", ".join(f"v{v}" for v in sorted(g["versions"]))
                    g["target_name"] = f"{g['target_name']} ({versions_str})"
                if "versions" in g:
                    del g["versions"]
                findings_list.append(g)

            processed_repositories.append({
                "name": display_name,
                "counters": repo_counters,
                "total_findings": sum(repo_counters.values()),
                "findings": findings_list,
            })

    # Renderização com Jinja2 
    templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
    if not os.path.exists(templates_dir):
        templates_dir = "templates"

    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template(template_name)

    html_content = template.render(
        generated_at=datetime.now().strftime("%d/%m/%Y %H:%M"),
        global_counters=global_counters,
        total_global_findings=sum(global_counters.values()),
        repositories=processed_repositories,
        sarif_json_raw=json_base64,                  # String sanitizada em linha única 
        filename=os.path.basename(json_path)
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path