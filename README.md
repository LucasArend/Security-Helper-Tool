# Security Helper Tool

A **Security Helper Tool** é um utilitário em Python para processar, visualizar e editar relatórios de segurança no padrão SARIF gerados por ferramentas de análise estática e de dependências.

## Funcionalidades

- **Consolidação de Relatórios:** Agrupamento de vulnerabilidades por repositório e por alvo/componente afetado.
- **Suporte a Múltiplas Ferramentas:** Identificação e processamento de achados originados por Trivy (SCA) e Semgrep (SAST).
- **Filtros:** Filtragem dinâmica na interface por tipo de ferramenta e por nível de severidade (Critical, High, Medium, Low, Warning).
- **Modo de Edição e Exportação:** Alteração e exportação de dados estruturados com persistência independente dos campos `shortDescription` e `fullDescription` no esquema SARIF.

## Arquitetura e Dependências

O core da ferramenta é desenvolvido em Python 3.

- **Jinja2:** Engine para renderização dos dados processados no template HTML.
- **urllib.parse:** Tratamento de caminhos de arquivos e URLs de referência das regras.
- **Frontend:** HTML5, CSS3 (Variáveis nativas e Flexbox) e JavaScript Vanilla para manipulação do DOM e lógica dos filtros.

## Execução do Projeto

### Pré-requisitos
Ambiente Windows com WSL (Windows Subsystem for Linux) rodando a distribuição Ubuntu.

### Passos para rodar

1. Instale a dependência do Jinja2 no ambiente do seu WSL:
   ```bash
   pip3 install jinja2
