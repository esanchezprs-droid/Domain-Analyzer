import subprocess
import sys
import socket
import re
import requests
from datetime import datetime
from urllib.parse import quote, urljoin
import ssl
from bs4 import BeautifulSoup
import time

def validar_dominio(dominio):
    """Valida que el input sea un dominio válido"""
    if len(dominio) < 1 or len(dominio) > 253:
        return False
    patron = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(patron, dominio))

def obtener_ip_socket(dominio):
    """Método Python puro - IPs"""
    try:
        ips = socket.gethostbyname_ex(dominio)
        return ips[2]
    except socket.gaierror:
        return []

def obtener_whois_api(dominio):
    """WHOIS via API gratuita"""
    try:
        url = f"https://whoisjson.com/v1/{quote(dominio)}"
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; DomainAnalyzer)'}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def parsear_whois_api(data):
    if not data or 'domain' not in data: return None
    info = {}
    info['Dominio'] = data.get('domain', 'N/A')
    info['Estado'] = data.get('status', 'N/A')
    info['Creado'] = data.get('created_at', 'N/A')
    info['Expira'] = data.get('updated_at', 'N/A')
    info['Registrar'] = data.get('registrar', {}).get('name', 'N/A')
    info['Servidores DNS'] = ', '.join(data.get('nameservers', []))
    registrant = data.get('registrant', {})
    info['Registrante'] = registrant.get('name', 'Privado')
    info['Email'] = registrant.get('email', 'Privado')
    info['País'] = registrant.get('country', 'N/A')
    return info

def geolocalizar_ip(ip):
    """Geolocalización IP"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'IP': ip, 'País': data.get('country', 'N/A'), 'Código': data.get('countryCode', 'N/A'),
                    'Región': data.get('regionName', 'N/A'), 'Ciudad': data.get('city', 'N/A'),
                    'Latitud': data.get('lat', 'N/A'), 'Longitud': data.get('lon', 'N/A'),
                    'ISP': data.get('isp', 'N/A'), 'Organización': data.get('org', 'N/A')
                }
    except: pass
    return None

def obtener_ssl(dominio):
    """Análisis Certificado SSL"""
    print(f"\n🔒 Analizando Certificado SSL para: **{dominio}**")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
        if not cert: return
        
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        ahora = datetime.utcnow()
        dias_restantes = (not_after - ahora).days
        estado = "✅ Válido" if ahora < not_after else "❌ Expirado"
        if dias_restantes < 30: estado += " ⚠️ Expira pronto"
        
        info = {
            'Versión': cert.get('version', 'N/A'),
            'Sujeto': ', '.join([f"{k}: {v}" for k, v in cert.get('subject', [])]),
            'Emisor': ', '.join([f"{k}: {v}" for k, v in cert.get('issuer', [])]),
            'Válido Desde': not_before.strftime('%Y-%m-%d'),
            'Válido Hasta': not_after.strftime('%Y-%m-%d'),
            'Días Restantes': dias_restantes,
            'Estado': estado,
            'Nombres Alternativos': ', '.join([name[1] for name in cert.get('subjectAltName', [])]) or 'N/A'
        }
        
        print("\n📜 **DETALLES CERTIFICADO**")
        print(f"{'Campo':<20} {'Valor':<40}")
        print("-" * 60)
        for campo, valor in info.items():
            print(f"{campo:<20} {str(valor):<40}")
        return True
    except Exception as e:
        print(f"❌ Error SSL: {e}")
        return False

# ==================== NUEVO: ANÁLISIS VULNERABILIDADES ====================
def analizar_vulnerabilidades(dominio):
    """Análisis completo OWASP Top 10 + Security Headers"""
    print(f"\n🛡️ **ANÁLISIS DE VULNERABILIDADES WEB**")
    print("=" * 70)
    
    base_url = f"https://{dominio}"
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (DomainAnalyzer)'})
    
    vulnerabilidades = []
    puntuacion = 100
    
    # 1. SECURITY HEADERS (Crítico)
    try:
        response = session.get(base_url, timeout=10, verify=False)
        headers = response.headers
        
        # HSTS
        hsts = headers.get('Strict-Transport-Security', '').lower()
        if 'max-age' not in hsts: 
            vulnerabilidades.append("❌ HSTS ausente - Man-in-the-Middle")
            puntuacion -= 15
        
        # CSP
        csp = headers.get('Content-Security-Policy')
        if not csp: 
            vulnerabilidades.append("❌ CSP ausente - XSS posible")
            puntuacion -= 12
        
        # X-Frame-Options
        xfo = headers.get('X-Frame-Options')
        if not xfo: 
            vulnerabilidades.append("❌ X-Frame ausente - Clickjacking")
            puntuacion -= 10
        
        # X-Content-Type-Options
        xcto = headers.get('X-Content-Type-Options')
        if xcto != 'nosniff': 
            vulnerabilidades.append("❌ X-Content-Type mal configurado - MIME Sniffing")
            puntuacion -= 8
        
        # Referrer-Policy
        rp = headers.get('Referrer-Policy')
        if not rp: 
            vulnerabilidades.append("⚠️ Referrer-Policy ausente - Privacidad")
            puntuacion -= 5
        
    except: 
        vulnerabilidades.append("❌ No se pudo analizar headers")
        puntuacion -= 20
    
    # 2. MÉTODOS HTTP EXpuestos
    try:
        methods = []
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE']:
            try:
                resp = session.options(base_url, timeout=5)
                if resp.status_code == 200 and method in resp.headers.get('Allow', ''):
                    methods.append(method)
            except: pass
        
        if 'TRACE' in methods:
            vulnerabilidades.append("🚨 TRACE habilitado - XST Attack")
            puntuacion -= 18
        if len(methods) > 2:
            vulnerabilidades.append(f"⚠️ {len(methods)} métodos HTTP expuestos")
            puntuacion -= 8
    except: pass
    
    # 3. COOKIES SEGURAS
    cookies_seguras = True
    for cookie in response.cookies:
        if not cookie.secure: 
            cookies_seguras = False
            break
    if not cookies_seguras:
        vulnerabilidades.append("❌ Cookies sin Secure flag - MitM")
        puntuacion -= 10
    
    # 4. CORS MISCONFIG
    cors = headers.get('Access-Control-Allow-Origin', '')
    if cors == '*':
        vulnerabilidades.append("🚨 CORS * - Acceso no autorizado")
        puntuacion -= 15
    
    # 5. PRUEBAS INYECCIÓN (No destructivo)
    payloads = ["' OR 1=1--", "<script>alert(1)</script>", "../etc/passwd"]
    for payload in payloads[:2]:  # Solo 2 para velocidad
        try:
            test_url = urljoin(base_url, f"?q={payload}")
            resp = session.get(test_url, timeout=5)
            if any(p in resp.text.lower() for p in ['error', 'warning', 'syntax']):
                vulnerabilidades.append(f"⚠️ Posible {payload[:20]}... inyección")
                puntuacion -= 10
                break
        except: pass
    
    # 6. SERVER INFO LEAK
    server = headers.get('Server', '')
    if server and len(server) > 5:
        vulnerabilidades.append(f"ℹ️ Server expuesto: {server}")
        puntuacion -= 3
    
    # MOSTRAR RESULTADOS
    color = "🟢" if puntuacion >= 80 else "🟡" if puntuacion >= 60 else "🔴"
    print(f"\n{color} **PUNTUACIÓN SEGURIDAD: {puntuacion}/100**")
    print("-" * 70)
    
    if vulnerabilidades:
        print("📋 **VULNERABILIDADES DETECTADAS:**")
        for i, vuln in enumerate(vulnerabilidades, 1):
            print(f"  {i:2d}. {vuln}")
    else:
        print("✅ ¡Excelente! No se detectaron vulnerabilidades críticas")
    
    print(f"\n💡 **RECOMENDACIONES:**")
    if puntuacion < 80:
        recs = [
            "• Activar HSTS: Strict-Transport-Security: max-age=31536000",
            "• Implementar CSP: Content-Security-Policy: default-src 'self'",
            "• Deshabilitar TRACE: Servidor config",
            "• Configurar CORS restrictivo",
            "• Actualizar software servidor"
        ]
        for rec in recs[:4]:
            print(f"  {rec}")
    
    return puntuacion

def obtener_ip(dominio):
    if not validar_dominio(dominio): return []
    print(f"🌐 Resolución DNS para: **{dominio}**")
    print("=" * 50)
    ips = obtener_ip_socket(dominio)
    if ips:
        print("📡 **IPs encontradas:**")
        for ip in ips: print(f"   → {ip}")
        print()
    else: print("❌ No se pudo resolver DNS")
    return ips

def mostrar_geolocalizacion(geo_data):
    if not geo_data: return
    print("\n🌍 **GEOLOCALIZACIÓN IP**")
    print(f"{'Campo':<18} {'Valor':<50}")
    print("-" * 70)
    campos = [
        ('IP', geo_data['IP']), ('País', f"{geo_data['País']} ({geo_data['Código']})"),
        ('Región', geo_data['Región']), ('Ciudad', geo_data['Ciudad']),
        ('ISP', geo_data['ISP']), ('📍 Coordenadas', f"{geo_data['Latitud']}, {geo_data['Longitud']}")
    ]
    for campo, valor in campos: print(f"{campo:<18} {valor:<50}")

def main(dominio):
    if not validar_dominio(dominio):
        print(f"❌ '{dominio}' no es un dominio válido")
        return
    
    print("🔍 **ANÁLISIS COMPLETO DE DOMINIO**")
    print("=" * 70)
    
    # 1. DNS
    ips = obtener_ip(dominio)
    
    # 2. WHOIS
    data_api = obtener_whois_api(dominio)
    if data_api:
        info = parsear_whois_api(data_api)
        print("\n👤 **INFORMACIÓN WHOIS**")
        print(f"{'Campo':<20} {'Valor':<40}")
        print("-" * 60)
        for campo in ['Dominio', 'Creado', 'Expira', 'Registrar', 'Registrante', 'País']:
            print(f"{campo:<20} {info.get(campo, 'N/A'):<40}")
    
    # 3. SSL
    obtener_ssl(dominio)
    
    # 4. VULNERABILIDADES **NUEVO**
    analizar_vulnerabilidades(dominio)
    
    # 5. GEO
    if ips: 
        geo_data = geolocalizar_ip(ips[0])
        mostrar_geolocalizacion(geo_data)
    
    print("\n" + "="*70)
    print("✅ **ANÁLISIS PROFESIONAL COMPLETADO!** 🎉")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Uso: python domain_analyzer.py <sitio-web>")
        print("Ejemplo: python domain_analyzer.py google.com")
        sys.exit(1)

    dominio = sys.argv[1].strip()
    main(dominio)