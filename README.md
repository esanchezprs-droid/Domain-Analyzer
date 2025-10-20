# Domain Analyzer

**Domain Analyzer** es una herramienta de línea de comandos escrita en Python que realiza un análisis completo de un dominio, incluyendo resolución DNS, información WHOIS, análisis de certificados SSL, geolocalización de IPs, y análisis de vulnerabilidades web.

## Características

- **Resolución DNS**: Obtiene todas las direcciones IP asociadas con un dominio.
- **Información WHOIS**: Recupera detalles del registro del dominio, incluyendo el registrador, el registrante, y los servidores DNS.
- **Análisis SSL**: Verifica la validez y los detalles del certificado SSL del dominio.
- **Geolocalización IP**: Proporciona información geográfica de las IPs obtenidas.
- **Análisis de Vulnerabilidades**: Evalúa la seguridad del dominio según las directrices OWASP Top 10 y recomienda mejoras.

## Requisitos

- Python 3.6+
- Bibliotecas Python: `requests`, `beautifulsoup4`, `ssl`, `socket`, `re`, `datetime`, `urllib.parse`

## Instalación

1. Clona este repositorio:
   ```sh
   git clone https://github.com/tu-usuario/domain-analyzer.git
   cd domain-analyzer