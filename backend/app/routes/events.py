from fastapi import APIRouter, Request, HTTPException, Response
import time
from app.database import get_connection
import requests
import secrets  # <--- Para criptografía segura
import string   # <--- Para manejar letras y símbolos
import hashlib  # <--- Para hashing de contraseñas
import re  # Para buscar patrones de texto como los correos electrónicos
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse  # Para desarmar y limpiar URLs
import os
import requests
from dotenv import load_dotenv

# --- CARGAR VARIABLES DE ENTORNO ---
load_dotenv()
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# --- FUNCIÓN DE DATA MASKING (PRIVACIDAD) ---
def enmascarar_datos_sensibles(url):
    if not url:
        return url
    
    # 1. Buscamos cualquier cosa que parezca un email y lo cambiamos
    url_limpia = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[EMAIL_CENSURADO]', url)

    # 2. Desarmamos la URL para revisar sus parámetros (lo que va después del "?")
    try:
        url_partes = urlparse(url_limpia)
        parametros = parse_qs(url_partes.query, keep_blank_values=True)
        
        # Lista de palabras peligrosas que queremos censurar
        palabras_clave = ['token', 'password', 'pass', 'key', 'session', 'auth']
        
        # Revisamos cada parámetro
        for clave in parametros:
            # Si el nombre del parámetro contiene alguna palabra peligrosa...
            if any(peligro in clave.lower() for peligro in palabras_clave):
                parametros[clave] = ['[CENSURADO]'] # Ocultamos su valor
                
        # Volvemos a armar la URL ya limpia
        nueva_query = urlencode(parametros, doseq=True)
        url_final = url_partes._replace(query=nueva_query)
        return urlunparse(url_final)
    except Exception as e:
        print(f"Error al limpiar URL: {e}")
        return url_limpia # Si algo falla, al menos devolvemos la URL sin emails

# --- FUNCIÓN DE GOOGLE  ---
API_KEY = "AIzaSyApNsq0VrpK4eSb2gTVT0UvDyLTZTPgycA"
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

def check_google_reputation(url):
    payload = {
        "client": {"clientId": "security-coach", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(SAFE_BROWSING_URL, json=payload, timeout=5)
        data = response.json()
        if "matches" in data:
            return "CRITICAL"
        return None
    except Exception as e:
        print(f"❌ Error de conexión con Google: {e}")
        return None
# Función de distancia de Levenshtein simple en Python
def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    # s1 es más largo
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

KNOWN_DOMAINS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "facebook.com",
    "caixabank.es",
    "santander.com",
    "bbva.es",
    "amazon.es"
]


def is_suspicious_domain(url_hostname):
    for domain in KNOWN_DOMAINS:
        distance = levenshtein_distance(url_hostname.lower(), domain.lower())
        if distance == 1:  # solo 1 letra diferente
            return True, domain
    return False, None

# --- SISTEMA ANTI-DOS (RATE LIMITING) ---
# Diccionario para recordar a qué hora hizo peticiones cada IP
historial_ips = {}

def verificar_rate_limit(request: Request):
    # Obtenemos la IP real del usuario que hace la petición
    ip_cliente = request.client.host
    tiempo_actual = time.time()

    # Si la IP ya ha venido antes, limpiamos sus peticiones de hace más de 10 segundos
    if ip_cliente in historial_ips:
        historial_ips[ip_cliente] = [t for t in historial_ips[ip_cliente] if tiempo_actual - t < 10]
    else:
        historial_ips[ip_cliente] = []

    # Si le quedan 5 o más peticiones recientes, le cerramos la puerta
    if len(historial_ips[ip_cliente]) >= 5:
        print(f"🚨 BLOQUEO ANTI-DOS: La IP {ip_cliente} está haciendo spam.")
        raise HTTPException(status_code=429, detail="Too Many Requests: Has superado el límite de seguridad.")

    # Si todo está bien, anotamos la hora de esta nueva petición
    historial_ips[ip_cliente].append(tiempo_actual)

router = APIRouter()

# --- FUNCIÓN PARA ENVIAR ALERTAS SOC POR TELEGRAM ---
def enviar_alerta_telegram(mensaje: str):
    print("\n--- INICIANDO ENVÍO DE TELEGRAM ---")
    print(f"Token detectado: {TELEGRAM_TOKEN}")
    print(f"Chat ID detectado: {TELEGRAM_CHAT_ID}")
    
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("❌ ERROR: Python no encuentra las claves. El .env no se está leyendo bien.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": mensaje,
        "parse_mode": "HTML"
    }
    
    try:
        print("📡 Enviando petición a los servidores de Telegram...")
        respuesta = requests.post(url, json=payload, timeout=5)
        print(f"Respuesta de Telegram: Código {respuesta.status_code}")
        print("-----------------------------------\n")
    except Exception as e:
        print(f"❌ Error interno al conectar con Telegram: {e}")

@router.post("/event")
async def receive_event(request: Request):
    # --- LLAMAMOS AL PORTERO ANTES DE DEJARLE PASAR ---
    verificar_rate_limit(request)
    try:
        data = await request.json()
    except:
        data = {}

    url = data.get("url", "")
    protocol = data.get("protocol", "")
        # ASEGURAMOS QUE LA URL TENGA PROTOCOLO ANTES DE ENVIARLA A GOOGLE
    full_url_for_google = url
    if protocol and not url.startswith("http"):
        full_url_for_google = f"{protocol}//{url}"

    # Limpiamos la URL para que el conteo de puntos sea real
    protocol = data.get("protocol", "")
    timestamp = data.get("timestamp", "")
    # Leemos si la extensión encontró campos de contraseña
    has_sensitive_inputs = data.get("has_sensitive_inputs", False) 
    # --- Leer las cabeceras de seguridad ---
    headers = data.get("headers", {})
    
    # 2. LÓGICA DE DETECCIÓN (CREAMOS LA ALERTA Y ASIGNAMOS GRAVEDAD)
    alert_msg = None
    severity = "INFO" # Por defecto

        # --- NUEVA LÓGICA DE GOOGLE ---
    google_severity = check_google_reputation(url)
    if google_severity == "CRITICAL":
        alert_msg = f"🛑 ¡BLOQUEADO POR SEGURIDAD GLOBAL!: Google ha reportado que {url} es un sitio peligroso."
        severity = "CRITICAL"
    

        # --- Detectar URLs con muchos puntos o muy largas (Típico Phishing) ---
    is_suspicious_pattern = url.count('.') > 4 or len(url) > 75
    if severity != "CRITICAL":
        
        # Check de Phishing (Levenshtein)
        # Extraemos solo el dominio (ej. paypal.com) para no confundir al algoritmo
        dominio = urlparse(full_url_for_google).netloc
        if not dominio:
            dominio = url

        # --- DETECCIÓN DE HOMÓGRAFOS (PUNYCODE) ---
        try:
            # Obligamos a Python a convertir el dominio a su formato interno real (IDNA)
            dominio_real = dominio.encode("idna").decode("ascii")
            if "xn--" in dominio_real:
                alert_msg = f"🛑 ¡ATAQUE HOMÓGRAFO!: El dominio oculta caracteres falsos ({dominio_real})."
                severity = "CRITICAL"
        except Exception as e:
            print(f"Error procesando Punycode: {e}")

        # Solo comprobamos la distancia de Levenshtein si NO ha saltado la alerta de Punycode
        if alert_msg is None:
            suspicious, original = is_suspicious_domain(dominio)
            if suspicious:
                if has_sensitive_inputs:
                    alert_msg = f"🛑 ¡SUPLANTACIÓN DETECTADA!: {url} intenta imitar a {original}. BLOQUEADO."
                    severity = "CRITICAL"
                else:
                    alert_msg = f"⚠️ SITIO SOSPECHOSO: {url} se parece mucho a {original}"
                    severity = "HIGH"    

        # Check de HTTP + Formularios (Añadimos "if alert_msg is None" para no pisar el anterior)
        if alert_msg is None and protocol == "http:":
            if has_sensitive_inputs:
                alert_msg = f"🛑 ¡PELIGRO CRÍTICO!: {url} es inseguro y pide contraseñas."
                severity = "CRITICAL"
            else:
                alert_msg = f"⚠️ CONEXIÓN INSEGURA: {url} no utiliza cifrado (HTTP)"
                severity = "MEDIUM"
        # --- Check de Cabeceras de Seguridad (Para webs HTTPS con formularios) ---
        if alert_msg is None and protocol == "https:" and has_sensitive_inputs:
            hsts_ok = headers.get("hsts", False)
            csp_ok = headers.get("csp", False)
            
            if not hsts_ok or not csp_ok:
                faltan = []
                if not hsts_ok: faltan.append("HSTS (Antirrobo de sesión)")
                if not csp_ok: faltan.append("CSP (Anti-XSS)")
                
                alert_msg = f"⚠️ PROTECCIÓN DÉBIL: La web pide contraseña pero carece de escudos clave: {', '.join(faltan)}."
                severity = "HIGH"        

# 3. GUARDAR EN LA BASE DE DATOS (CON PRIVACIDAD)
    # Pasamos la URL por nuestra función de limpieza antes de guardarla
    url_segura = enmascarar_datos_sensibles(url)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (url, protocol, timestamp, severity) VALUES (?, ?, ?, ?)",
        (url_segura, protocol, timestamp, severity) # <--- Usamos la url_segura
    )
    conn.commit()
    conn.close()

# --- DISPARAR ALERTA DE TELEGRAM SI ES CRÍTICO ---
    if severity == "CRITICAL":
        ip_cliente = request.client.host
        mensaje_tg = (
            f"🚨 <b>ALERTA CRÍTICA DE SEGURIDAD</b> 🚨\n\n"
            f"🖥️ <b>IP del Equipo:</b> {ip_cliente}\n"
            f"🌐 <b>Dominio Afectado:</b> {url}\n"
            f"📝 <b>Motivo:</b> {alert_msg}\n\n"
            f"🛡️ <i>Security Coach SOC Automático</i>"
        )
        # Llamamos al mensajero
        enviar_alerta_telegram(mensaje_tg)

    # 4. RESPONDER A LA EXTENSIÓN
    return {
        "status": "ok",
        "alert": alert_msg is not None,
        "message": alert_msg,
        "severity": severity
    }
@router.get("/stats")
async def get_stats():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Contamos por categorías
        cursor.execute("SELECT severity, COUNT(*) as total FROM events GROUP BY severity")
        rows = cursor.fetchall()
        
        # Inicializamos los contadores
        stats = {"total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        
        for row in rows:
            stats[row["severity"]] = row["total"]
            stats["total"] += row["total"]

                # 2. Leer las contraseñas generadas (IMPORTANTE)
        cursor.execute("SELECT value FROM stats WHERE key = 'passwords_generated'")
        row_pass = cursor.fetchone()
        if row_pass:
            stats["passwords_generated"] = row_pass["value"]

        conn.close()
        return stats
        
    except Exception as e:
        print(f"Error en stats: {e}")
        return {"total": "ERR", "passwords_generated": 0} # Si falla, devuelve esto para no romper el JS
    
def is_password_pwned(password): #comprobar si la contraseña ha sido filtrada usando k-Anonymity
    # 1. Crear el hash SHA-1 de la contraseña
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    # 2. Consultar a la API de Have I Been Pwned
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return False # Si la API falla, por precaución no bloqueamos
        
        # 3. Revisar si nuestro 'suffix' está en la respuesta
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                print(f"⚠️ ¡Contraseña filtrada detectada! Aparece {count} veces.")
                return True
        return False
    except Exception as e:
        print(f"❌ Error consultando HIBP: {e}")
        return False
# --- GENERADOR DE CONTRASEÑAS ---
def generate_secure_password(length=18):
    # Caracteres: Mayúsculas, minúsculas, números y símbolos
    alphabet = string.ascii_letters + string.digits + "!@#$%&*-_=+"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Verificamos que tenga al menos 1 de cada para asegurar robustez y que no este filtrada en HIBP
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in "!@#$%&*-_=+" for c in password)
                and not is_password_pwned(password)): 
            return password

@router.get("/generate-password")
async def get_password():
    password = generate_secure_password(18) # 18 caracteres para máxima entropía
        # --- Sumar 1 al contador ---
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE stats SET value = value + 1 WHERE key = 'passwords_generated'")
    conn.commit()
    conn.close()
    return {"password": password}

from datetime import datetime 

from datetime import datetime

# --- EXPORTAR DASHBOARD EJECUTIVO (ESTILO WAZUH) ---
@router.get("/export")
async def export_events():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Filtramos los eventos de navegación segura (INFO)
        cursor.execute("""
            SELECT timestamp, url, protocol, severity 
            FROM events 
            WHERE severity != 'INFO' 
            ORDER BY timestamp DESC LIMIT 100
        """)
        rows = cursor.fetchall()
        conn.close()

        # 1. Calculamos las estadísticas para la gráfica y las tarjetas
        count_critical = 0
        count_high = 0
        count_medium = 0
        filas_html = ""

        for row in rows:
            sev = row['severity']
            if sev == 'CRITICAL': count_critical += 1
            elif sev == 'HIGH': count_high += 1
            elif sev == 'MEDIUM': count_medium += 1

            # Limpiamos la fecha
            fecha_limpia = row['timestamp']
            if "T" in fecha_limpia:
                try:
                    fecha_obj = datetime.strptime(fecha_limpia.split('.')[0], "%Y-%m-%dT%H:%M:%S")
                    fecha_limpia = fecha_obj.strftime("%d/%m/%Y %H:%M:%S")
                except:
                    pass

            # Clases de color para las etiquetas
            badge_class = "bg-medium"
            if sev == "CRITICAL": badge_class = "bg-critical"
            elif sev == "HIGH": badge_class = "bg-high"

            # Creamos cada fila de la tabla
            filas_html += f"""
                <tr>
                    <td class="fecha">{fecha_limpia}</td>
                    <td class="url">{row['url']}</td>
                    <td><span class="protocol">{row['protocol'].replace(':', '')}</span></td>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                </tr>
            """
            
        total_events = count_critical + count_high + count_medium

        # 2. Construimos el diseño (CSS estilo Dashboard)
        html_top = """
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <title>Security Coach | Threat Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                :root {
                    --bg-main: #f1f5f9;
                    --card-bg: #ffffff;
                    --text-main: #1e293b;
                    --border: #e2e8f0;
                    --critical: #ef4444;
                    --high: #f97316;
                    --medium: #eab308;
                }
                body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: var(--bg-main); color: var(--text-main); margin: 0; padding: 30px; }
                .container { max-width: 1300px; margin: 0 auto; }
                
                /* Cabecera */
                .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 30px; background: #0f172a; color: white; padding: 20px 30px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
                .header h1 { margin: 0; font-size: 1.5rem; font-weight: 600; letter-spacing: 0.5px; }
                
                /* Tarjetas KPI */
                .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
                .kpi-card { background: var(--card-bg); padding: 25px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 2px 4px rgba(0,0,0,0.02); display: flex; flex-direction: column; align-items: center; }
                .kpi-title { font-size: 0.85rem; color: #64748b; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
                .kpi-value { font-size: 2.8rem; font-weight: 800; }
                
                /* Layout principal (Gráfica + Tabla) */
                .content-grid { display: grid; grid-template-columns: 1fr 2fr; gap: 20px; }
                .panel { background: var(--card-bg); padding: 25px; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
                .panel-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 20px; color: #334155; border-bottom: 2px solid var(--bg-main); padding-bottom: 15px; }
                
                /* Tabla de datos */
                .table-container { overflow-x: auto; max-height: 500px; }
                table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
                th { padding: 15px; background-color: #f8fafc; color: #475569; font-weight: 600; position: sticky; top: 0; box-shadow: 0 1px 0 var(--border); }
                td { padding: 15px; border-bottom: 1px solid var(--border); }
                tr:hover td { background-color: #f8fafc; }
                .fecha { color: #64748b; white-space: nowrap; }
                .url { font-family: monospace; font-size: 0.95rem; color: #2563eb; word-break: break-all; }
                .protocol { background: #e2e8f0; color: #475569; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }
                
                /* Badges */
                .badge { padding: 6px 12px; border-radius: 50px; font-weight: 700; font-size: 0.75rem; color: white; display: inline-block; text-align: center; min-width: 80px; text-transform: uppercase; letter-spacing: 0.5px; }
                .bg-critical { background-color: var(--critical); box-shadow: 0 2px 5px rgba(239, 68, 68, 0.4); }
                .bg-high { background-color: var(--high); }
                .bg-medium { background-color: var(--medium); color: #854d0e; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Security Coach | Threat Intelligence</h1>
                    <span style="background: rgba(255,255,255,0.2); padding: 8px 15px; border-radius: 20px; font-size: 0.85rem;">Reporte Automático</span>
                </div>
        """

        # 3. Inyectamos los datos dinámicos en las tarjetas
        html_middle = f"""
                <div class="kpi-grid">
                    <div class="kpi-card">
                        <div class="kpi-title">Total Interceptados</div>
                        <div class="kpi-value" style="color: #0f172a;">{total_events}</div>
                    </div>
                    <div class="kpi-card" style="border-bottom: 4px solid var(--critical);">
                        <div class="kpi-title">Ataques Críticos</div>
                        <div class="kpi-value" style="color: var(--critical);">{count_critical}</div>
                    </div>
                    <div class="kpi-card" style="border-bottom: 4px solid var(--high);">
                        <div class="kpi-title">Riesgo Alto</div>
                        <div class="kpi-value" style="color: var(--high);">{count_high}</div>
                    </div>
                    <div class="kpi-card" style="border-bottom: 4px solid var(--medium);">
                        <div class="kpi-title">Riesgo Medio</div>
                        <div class="kpi-value" style="color: var(--medium);">{count_medium}</div>
                    </div>
                </div>

                <div class="content-grid">
                    <div class="panel">
                        <div class="panel-title">📊 Distribución de Riesgo</div>
                        <div style="position: relative; height: 350px; width: 100%; display: flex; justify-content: center; align-items: center;">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                    
                    <div class="panel table-container">
                        <div class="panel-title">📋 Últimos Incidentes Registrados</div>
                        <table>
                            <thead>
                                <tr>
                                    <th>Fecha y Hora</th>
                                    <th>URL Afectada</th>
                                    <th>Prot.</th>
                                    <th>Gravedad</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filas_html}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        """

        # 4. Inyectamos los valores en Javascript para que dibuje el donut
        html_bottom = f"""
            <script>
                const ctx = document.getElementById('severityChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Crítico', 'Alto', 'Medio'],
                        datasets: [{{
                            data: [{count_critical}, {count_high}, {count_medium}],
                            backgroundColor: ['#ef4444', '#f97316', '#eab308'],
                            borderWidth: 0,
                            hoverOffset: 10
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '75%',
                        plugins: {{
                            legend: {{ position: 'bottom', labels: {{ padding: 20, font: {{ size: 14 }} }} }}
                        }}
                    }}
                }});
            </script>
        </body>
        </html>
        """

        # 5. Unimos todo y lo enviamos
        final_html = html_top + html_middle + html_bottom

        return Response(
            content=final_html.encode('utf-8'), 
            media_type="text/html", 
            headers={"Content-Disposition": "attachment; filename=Security_Coach_Dashboard.html"}
        )
    except Exception as e:
        print(f"Error exportando HTML: {e}")
        raise HTTPException(status_code=500, detail="Error al generar el reporte")