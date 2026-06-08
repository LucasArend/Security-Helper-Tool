# Security Helper Tool

A **Security Helper Tool** é um utilitário em Python para processar, visualizar e editar relatórios de segurança no padrão SARIF gerados por ferramentas de análise estática e de dependências.

## Funcionalidades

- **Clonagem em Massa Automatizada:** Download automático de todos os repositórios vinculados a um projeto ou organização do Azure DevOps a partir de uma única URL de serviço.
- **Consolidação de Relatórios:** Agrupamento de vulnerabilidades por repositório e por alvo/componente afetado.
- **Suporte a Múltiplas Ferramentas:** Identificação e processamento de achados originados por Trivy (SCA) e Semgrep (SAST).
- **Filtros:** Filtragem dinâmica na interface por tipo de ferramenta e por nível de severidade (Critical, High, Medium, Low, Warning).
- **Modo de Edição e Exportação:** Alteração e exportação de dados estruturados com persistência independente dos campos no esquema SARIF.

## Arquitetura e Dependências

O core da ferramenta é desenvolvido em Python 3.

- **Jinja2:** Engine para renderização dos dados processados no template HTML.
- **urllib.parse:** Tratamento de caminhos de arquivos e URLs de referência das regras.
- **Frontend:** HTML5, CSS3 (Variáveis nativas e Flexbox) e JavaScript Vanilla para manipulação do DOM e lógica dos filtros.

## Execução do Projeto

### Pré-requisitos
Ambiente Windows com WSL (Windows Subsystem for Linux) rodando a distribuição Ubuntu.

### Passos para rodar

### 1. Pré-requisitos do Sistema
A execução de todo o ecossistema exige os seguintes requisitos conforme o sistema operacional:
- **Windows:** Obrigatório o uso de **WSL2 com Ubuntu**. Não utilize o PowerShell/CMD nativo, pois as regras do Semgrep dependem de ferramentas Unix.
- **Linux:** Distribuição com Python 3.8+.
- **macOS:** Versão 11 (Big Sur) ou superior.

### 2. Configuração de Dependências Base (WSL/Linux)
Verifique a versão do Python instalada:

```Bash
python3 --version
```

Caso não esteja instalado ou o comando falhe, execute:

```Bash
sudo apt update
sudo apt install python3 python3-pip pipx -y
```

3. Configuração do Git (Azure DevOps)
Certifique-se de que sua chave SSH pública está cadastrada em:

    Azure DevOps → User Settings → SSH public keys

Valide a conectividade com o comando:
```Bash
ssh -T git@ssh.dev.azure.com
```

4. Instalação do Semgrep

Instale o CLI via pipx e realize a autenticação:

```Bash
pipx install semgrep
semgrep login
```

Como o ambiente de terminal não possui navegador nativo, o comando gerará uma URL. Copie o link completo, cole no navegador do seu sistema hospedeiro, efetue o login e o terminal confirmará a autenticação automaticamente.

5. Instalação do Trivy
Adicione o repositório oficial e instale o pacote:
```Bash

sudo apt-get install wget gnupg -y

wget -qO - [https://aquasecurity.github.io/trivy-repo/deb/public.key](https://aquasecurity.github.io/trivy-repo/deb/public.key) | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] [https://aquasecurity.github.io/trivy-repo/deb](https://aquasecurity.github.io/trivy-repo/deb) $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list

sudo apt-get update
sudo apt-get install trivy -y
```

Execução do Projeto

    Instale a biblioteca do Jinja2 no ambiente do seu terminal:
    Bash

    pip3 install jinja2

    Execute o script principal da ferramenta:
    Bash

    python3 main.py

✒️ Autor

    Lucas Arend

📄 Licença

Este projeto está sob a licença MIT.

<img width="462" height="414" alt="image" src="https://github.com/user-attachments/assets/2383e230-c4c5-4e17-9ab9-425cd495907c" />
<img width="595" height="396" alt="image" src="https://github.com/user-attachments/assets/cd0577c2-af3b-4a57-afd0-4c4c4da0dcf4" />
<img width="612" height="517" alt="image" src="https://github.com/user-attachments/assets/a02a9ca2-073f-4a20-a613-826cf6c571ee" />
<img width="1316" height="610" alt="image" src="https://github.com/user-attachments/assets/2beb36f7-eb58-4c22-875a-948018eb1fa0" />
<img width="1315" height="554" alt="image" src="https://github.com/user-attachments/assets/d4331d85-ade1-4be4-8c3e-03c2cb16895e" />



