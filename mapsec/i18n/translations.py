"""Translation dictionaries for Mapsec GUI."""

# English (default)
EN = {
    # Header
    "subtitle": "Security Reconnaissance Toolkit",

    # Tabs
    "tab_scan": "Scan",
    "tab_results": "Results",

    # Target section
    "target_label": "Target",
    "target_placeholder": "e.g. example.com  or  192.168.1.0/24",

    # Buttons
    "btn_scan": "\u25b6  Scan",
    "btn_cancel": "\u2715  Cancel",
    "btn_settings": "\u2699  Settings",
    "btn_analyze": "\U0001f50d  Analyze",
    "btn_analyzing": "\u23f3  Analyzing...",
    "btn_export_json": "Export JSON",
    "btn_export_html": "Export HTML Report",
    "btn_export_pdf": "Export PDF Report",
    "btn_save": "Save",
    "btn_clear_all": "Clear All",
    "btn_cancel_action": "Cancel",

    # Plugins section
    "plugins_label": "Plugins",
    "plugin_nmap": "\u2022 nmap \u2014 port scan",
    "plugin_dns": "\u2022 dns \u2014 enumeration",
    "plugin_vt": "\u2022 vt \u2014 threat intel",
    "plugin_whois": "\u2022 whois \u2014 registration info",
    "plugin_banner": "\u2022 banner \u2014 identify services",
    "plugin_ssl": "\u2022 ssl \u2014 certificate & protocols",
    "plugin_headers": "\u2022 headers \u2014 security headers",
    "plugin_shodan": "\u2022 shodan \u2014 IoT / device search",
    "plugin_cve": "\u2022 cve \u2014 vulnerability lookup",
    "plugin_vt_no_key": "\u2022 vt \u2014 no API key",
    "plugin_shodan_no_key": "\u2022 shodan \u2014 no API key",

    # Status indicators
    "status_nmap": "\u25cb nmap",
    "status_dns": "\u25cb dns",
    "status_vt": "\u25cb vt",
    "status_whois": "\u25cb whois",
    "status_banner": "\u25cb banner",
    "status_ssl": "\u25cb ssl",
    "status_headers": "\u25cb headers",
    "status_shodan": "\u25cb shodan",
    "status_cve": "\u25cb cve",

    # Progress
    "scanning": "Scanning...",
    "ready": "Ready",
    "cancelled": "Cancelled",
    "error": "Error",

    # Activity Log
    "activity_log": "Activity Log",

    # Settings dialog
    "settings_title": "Configuration",
    "settings_vt_key": "VirusTotal API Key",
    "settings_vt_hint": "Get a free key at virustotal.com",
    "settings_shodan_key": "Shodan API Key (optional)",
    "settings_shodan_hint": "Free tier available at account.shodan.io",
    "settings_llm_provider": "LLM Analysis Provider (optional)",
    "settings_llm_hint": "For deep security analysis with AI recommendations",
    "settings_model": "Model (optional)",
    "settings_api_key": "API keys and integrations",
    "settings_paste_key": "Paste your API key here",
    "settings_paste_llm_key": "Paste your LLM API key here",
    "settings_paste_shodan_key": "Paste your Shodan API key here",
    "settings_saved": "Saved",
    "settings_all_cleared": "All keys cleared",

    # Results
    "results_no_results": "No results yet",
    "results_details": "\u25b6  Details",

    # Analysis
    "analysis_no_software": "No software versions detected for CVE lookup.",
    "analysis_scan_failed": "Scan Failed",

    # Results panel - Nmap
    "nmap_target": "Target",
    "nmap_hostname": "Hostname",
    "nmap_open_ports": "Open Ports",
    "nmap_port_list": "Open Ports",
    "nmap_no_hosts": "No hosts found",

    # Results panel - DNS
    "dns_domain": "Domain",
    "dns_total_records": "Total Records",
    "dns_subdomains": "Subdomains",
    "dns_unique_ips": "Unique IPs",
    "dns_records": "Records",
    "dns_discovered_subdomains": "Discovered Subdomains",

    # Results panel - VT
    "vt_threat_level": "Threat Level",
    "vt_malicious": "Malicious",
    "vt_suspicious": "Suspicious",
    "vt_harmless": "Harmless",
    "vt_undetected": "Undetected",
    "vt_registrar": "Registrar",
    "vt_categories": "Categories",
    "vt_known_vulns": "Known Vulnerabilities",

    # Results panel - SSL
    "ssl_protocol": "Protocol",
    "ssl_cipher": "Cipher",
    "ssl expiresIn": "Expires In",
    "ssl_certificate": "Certificate",
    "ssl_issuer": "Issuer",
    "ssl_subject": "Subject",
    "ssl_valid_from": "Valid From",
    "ssl_valid_to": "Valid To",
    "ssl_serial": "Serial",
    "ssl_san": "Subject Alternative Names",
    "ssl_flags": "Flags",
    "ssl_weak_protocols": "Weak Protocols Detected",
    "ssl_warnings": "Warnings",
    "ssl_expired": "EXPIRED",
    "ssl_self_signed": "SELF-SIGNED",

    # Results panel - Headers
    "headers_grade": "Grade",
    "headers_present": "Present",
    "headers_missing": "Missing",
    "headers_security_headers": "Security Headers",
    "headers_leaked": "Leaked Information",
    "headers_warnings": "Warnings",

    # Results panel - Whois
    "whois_registrar": "Registrar",
    "whois_created": "Created",
    "whois_expires": "Expires",
    "whois_name_servers": "Name Servers",
    "whois_registrant": "Registrant",
    "whois_registration_info": "Registration Info",

    # Results panel - Banner
    "banner_open_ports": "Open Ports",
    "banner_service_banners": "Service Banners",
    "banner_port": "Port",
    "banner_service": "Service",
    "banner_banner": "Banner",

    # Results panel - Shodan
    "shodan_ip": "IP",
    "shodan_org": "Organization",
    "shodan_isp": "ISP",
    "shodan_os": "OS",
    "shodan_country": "Country",
    "shodan_city": "City",
    "shodan_ports": "Ports",
    "shodan_services": "Services",
    "shodan_vulns": "Vulnerabilities Found",

    # Results panel - CVE
    "cve_software": "Software Detected",
    "cve_total": "Total CVEs",
    "cve_critical": "Critical",
    "cve_high": "High",
    "cve_medium": "Medium",
    "cve_low": "Low",
    "cve_description": "Description",
    "cve_severity": "Severity",
    "cve_source": "Source",

    # Results panel - Exploit
    "exploit_title": "Exploit Scenarios",
    "exploit_how": "How an attacker exploits this:",
    "exploit_impact": "Potential impact:",
    "exploit_no_cves": "No CVEs to analyze. Run the CVE plugin first.",
    "exploit_source_llm": "AI-powered",
    "exploit_source_template": "Pattern-based",

    # Results panel - common
    "results_recommendation": "Recommendation: ",
    "results_error": "Error",
    "results_categories": "Categories",

    # Summary card display names (used in _extract_summary)
    "summary_display_nmap": "Port Scan",
    "summary_display_dns": "DNS Enum",
    "summary_display_vt": "Threat Intel",
    "summary_display_whois": "Whois Lookup",
    "summary_display_banner": "Banners",
    "summary_display_ssl": "SSL/TLS",
    "summary_display_headers": "Security Headers",
    "summary_display_shodan": "Shodan",
    "summary_display_cve": "CVE Lookup",
    "summary_display_exploit": "Exploit Scenarios",

    # Summary card metric strings
    "summary_open_ports": "open ports",
    "summary_records": "records",
    "summary_subdomains": "subdomains",
    "summary_malicious": "malicious",
    "summary_suspicious": "suspicious",
    "summary_clean": "CLEAN",
    "summary_name_servers": "name servers",
    "summary_services_found": "services found",
    "summary_until_expiry": "until expiry",
    "summary_missing": "missing",
    "summary_cves": "CVEs",
    "summary_critical": "critical",
    "summary_unknown_error": "Unknown error",
    "summary_grade": "Grade",
    "summary_ports": "ports",

    # Analysis report
    "analysis_score": "Security Score",
    "analysis_summary": "Executive Summary",
    "analysis_findings": "Findings",
    "analysis_no_llm": "(rules-only analysis)",
    "analysis_llm_analysis": "AI Analysis",

    # Version
    "version": "v0.1.0",
}

# Portuguese (Brazil)
PT_BR = {
    # Header
    "subtitle": "Ferramenta de Reconhecimento de Seguran\u00e7a",

    # Tabs
    "tab_scan": "An\u00e1lise",
    "tab_results": "Resultados",

    # Target section
    "target_label": "Alvo",
    "target_placeholder": "ex. example.com  ou  192.168.1.0/24",

    # Buttons
    "btn_scan": "\u25b6  Analisar",
    "btn_cancel": "\u2715  Cancelar",
    "btn_settings": "\u2699  Configura\u00e7\u00f5es",
    "btn_analyze": "\U0001f50d  Analisar",
    "btn_analyzing": "\u23f3  Analisando...",
    "btn_export_json": "Exportar JSON",
    "btn_export_html": "Exportar Relat\u00f3rio HTML",
    "btn_export_pdf": "Exportar Relat\u00f3rio PDF",
    "btn_save": "Salvar",
    "btn_clear_all": "Limpar Tudo",
    "btn_cancel_action": "Cancelar",

    # Plugins section
    "plugins_label": "Plugins",
    "plugin_nmap": "\u2022 nmap \u2014 varredura de portas",
    "plugin_dns": "\u2022 dns \u2014 enumera\u00e7\u00e3o",
    "plugin_vt": "\u2022 vt \u2014 intelig\u00eancia de amea\u00e7as",
    "plugin_whois": "\u2022 whois \u2014 info de registro",
    "plugin_banner": "\u2022 banner \u2014 identificar servi\u00e7os",
    "plugin_ssl": "\u2022 ssl \u2014 certificado & protocolos",
    "plugin_headers": "\u2022 headers \u2014 cabe\u00e7alhos de seguran\u00e7a",
    "plugin_shodan": "\u2022 shodan \u2014 busca IoT / dispositivos",
    "plugin_cve": "\u2022 cve \u2014 consulta de vulnerabilidades",
    "plugin_vt_no_key": "\u2022 vt \u2014 sem chave API",
    "plugin_shodan_no_key": "\u2022 shodan \u2014 sem chave API",

    # Status indicators
    "status_nmap": "\u25cb nmap",
    "status_dns": "\u25cb dns",
    "status_vt": "\u25cb vt",
    "status_whois": "\u25cb whois",
    "status_banner": "\u25cb banner",
    "status_ssl": "\u25cb ssl",
    "status_headers": "\u25cb headers",
    "status_shodan": "\u25cb shodan",
    "status_cve": "\u25cb cve",

    # Progress
    "scanning": "Escaneando...",
    "ready": "Pronto",
    "cancelled": "Cancelado",
    "error": "Erro",

    # Activity Log
    "activity_log": "Log de Atividades",

    # Settings dialog
    "settings_title": "Configura\u00e7\u00f5es",
    "settings_vt_key": "Chave API do VirusTotal",
    "settings_vt_hint": "Obtenha uma chave gr\u00e1tica em virustotal.com",
    "settings_shodan_key": "Chave API do Shodan (opcional)",
    "settings_shodan_hint": "Tier gratuito dispon\u00edvel em account.shodan.io",
    "settings_llm_provider": "Provedor de An\u00e1lise LLM (opcional)",
    "settings_llm_hint": "Para an\u00e1lise profunda de seguran\u00e7a com recomenda\u00e7\u00f5es de IA",
    "settings_model": "Modelo (opcional)",
    "settings_api_key": "Chaves de API e integra\u00e7\u00f5es",
    "settings_paste_key": "Cole sua chave de API aqui",
    "settings_paste_llm_key": "Cole sua chave de API LLM aqui",
    "settings_paste_shodan_key": "Cole sua chave de API Shodan aqui",
    "settings_saved": "Salvo",
    "settings_all_cleared": "Todas as chaves limpas",

    # Results
    "results_no_results": "Nenhum resultado ainda",
    "results_details": "\u25b6  Detalhes",

    # Analysis
    "analysis_no_software": "Nenhuma vers\u00e3o de software detectada para consulta CVE.",
    "analysis_scan_failed": "An\u00e1lise Falhou",

    # Results panel - Nmap
    "nmap_target": "Alvo",
    "nmap_hostname": "Hostname",
    "nmap_open_ports": "Portas Abertas",
    "nmap_port_list": "Portas Abertas",
    "nmap_no_hosts": "Nenhum host encontrado",

    # Results panel - DNS
    "dns_domain": "Dom\u00ednio",
    "dns_total_records": "Total de Registros",
    "dns_subdomains": "Subdom\u00ednios",
    "dns_unique_ips": "IPs \u00fanicos",
    "dns_records": "Registros",
    "dns_discovered_subdomains": "Subdom\u00ednios Descobertos",

    # Results panel - VT
    "vt_threat_level": "N\u00edvel de Amea\u00e7a",
    "vt_malicious": "Malicioso",
    "vt_suspicious": "Suspeito",
    "vt_harmless": "Inofensivo",
    "vt_undetected": "N\u00e3o Detectado",
    "vt_registrar": "Registrador",
    "vt_categories": "Categorias",
    "vt_known_vulns": "Vulnerabilidades Conhecidas",

    # Results panel - SSL
    "ssl_protocol": "Protocolo",
    "ssl_cipher": "Cifra",
    "ssl expiresIn": "Expira Em",
    "ssl_certificate": "Certificado",
    "ssl_issuer": "Emissor",
    "ssl_subject": "Assunto",
    "ssl_valid_from": "V\u00e1lido De",
    "ssl_valid_to": "V\u00e1lido At\u00e9",
    "ssl_serial": "Serial",
    "ssl_san": "Nomes Alternativos do Assunto",
    "ssl_flags": "Flags",
    "ssl_weak_protocols": "Protocolos Fracos Detectados",
    "ssl_warnings": "Avisos",
    "ssl_expired": "EXPIRADO",
    "ssl_self_signed": "AUTO-ASSINADO",

    # Results panel - Headers
    "headers_grade": "Nota",
    "headers_present": "Presentes",
    "headers_missing": "Ausentes",
    "headers_security_headers": "Cabe\u00e7alhos de Seguran\u00e7a",
    "headers_leaked": "Informa\u00e7\u00f5es Vazadas",
    "headers_warnings": "Avisos",

    # Results panel - Whois
    "whois_registrar": "Registrador",
    "whois_created": "Criado",
    "whois_expires": "Expira",
    "whois_name_servers": "Servidores DNS",
    "whois_registrant": "Registrante",
    "whois_registration_info": "Informa\u00e7\u00f5es de Registro",

    # Results panel - Banner
    "banner_open_ports": "Portas Abertas",
    "banner_service_banners": "Banners de servi\u00e7os",
    "banner_port": "Porta",
    "banner_service": "Servi\u00e7o",
    "banner_banner": "Banner",

    # Results panel - Shodan
    "shodan_ip": "IP",
    "shodan_org": "Organiza\u00e7\u00e3o",
    "shodan_isp": "ISP",
    "shodan_os": "SO",
    "shodan_country": "Pa\u00eds",
    "shodan_city": "Cidade",
    "shodan_ports": "Portas",
    "shodan_services": "Servi\u00e7os",
    "shodan_vulns": "Vulnerabilidades Encontradas",

    # Results panel - CVE
    "cve_software": "Software Detectado",
    "cve_total": "Total de CVEs",
    "cve_critical": "Cr\u00edtico",
    "cve_high": "Alto",
    "cve_medium": "M\u00e9dio",
    "cve_low": "Baixo",
    "cve_description": "Descri\u00e7\u00e3o",
    "cve_severity": "Severidade",
    "cve_source": "Fonte",

    # Results panel - Exploit
    "exploit_title": "Cen\u00e1rios de Explora\u00e7\u00e3o",
    "exploit_how": "Como um atacante explora isso:",
    "exploit_impact": "Impacto potencial:",
    "exploit_no_cves": "Nenhuma CVE para analisar. Execute o plugin CVE primeiro.",
    "exploit_source_llm": "Gerado por IA",
    "exploit_source_template": "Baseado em padr\u00f5es",

    # Results panel - common
    "results_recommendation": "Recomenda\u00e7\u00e3o: ",
    "results_error": "Erro",
    "results_categories": "Categorias",

    # Summary card display names (used in _extract_summary)
    "summary_display_nmap": "Varredura de Portas",
    "summary_display_dns": "Enumera\u00e7\u00e3o DNS",
    "summary_display_vt": "Intelig\u00eancia de Amea\u00e7as",
    "summary_display_whois": "Consulta Whois",
    "summary_display_banner": "Banners",
    "summary_display_ssl": "SSL/TLS",
    "summary_display_headers": "Cabe\u00e7alhos de Seguran\u00e7a",
    "summary_display_shodan": "Shodan",
    "summary_display_cve": "Consulta CVE",
    "summary_display_exploit": "Cen\u00e1rios de Explora\u00e7\u00e3o",

    # Summary card metric strings
    "summary_open_ports": "portas abertas",
    "summary_records": "registros",
    "summary_subdomains": "subdom\u00ednios",
    "summary_malicious": "maliciosos",
    "summary_suspicious": "suspeitos",
    "summary_clean": "LIMPO",
    "summary_name_servers": "servidores DNS",
    "summary_services_found": "servi\u00e7os encontrados",
    "summary_until_expiry": "at\u00e9 expirar",
    "summary_missing": "ausentes",
    "summary_cves": "CVEs",
    "summary_critical": "cr\u00edticos",
    "summary_unknown_error": "Erro desconhecido",
    "summary_grade": "Nota",
    "summary_ports": "portas",

    # Analysis report
    "analysis_score": "Pontua\u00e7\u00e3o de Seguran\u00e7a",
    "analysis_summary": "Resumo Executivo",
    "analysis_findings": "Constata\u00e7\u00f5es",
    "analysis_no_llm": "(an\u00e1lise apenas com regras)",
    "analysis_llm_analysis": "An\u00e1lise com IA",

    # Version
    "version": "v0.1.0",
}
