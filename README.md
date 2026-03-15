# 🛡️ Security Coach - Browser Threat Intelligence & SOC

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-Modern-009688.svg)
![Manifest](https://img.shields.io/badge/Chrome-Manifest_V3-4caf50.svg)

**Security Coach** es una solución de ciberseguridad integral compuesta por un agente EDR ligero (Extensión de Chrome) y un motor de análisis Backend (Python/FastAPI). Su objetivo es auditar, detectar y mitigar amenazas web en tiempo real, operando bajo principios de privacidad por diseño (*Privacy by Design*) y enviando telemetría a un Centro de Operaciones de Seguridad (SOC).

---

## ✨ Características Principales

### 👁️ Agente Frontend (Extensión Chrome)
* **Vigilante K-Anonymity:** Inspecciona contraseñas mecanografiadas y consulta la API de *Have I Been Pwned* enviando solo los primeros 5 caracteres del hash SHA-1, garantizando que la credencial nunca salga del equipo.
* **Escáner de Cabeceras de Red:** Intercepta tráfico en tiempo real mediante `chrome.webRequest` para auditar implementaciones de HSTS, CSP y X-Frame-Options al vuelo.
* **Mitigación Activa:** Inyección de *MutationObservers* en el DOM que bloquean automáticamente campos de contraseña (Disabled) ante amenazas críticas. Incluye un *Kill Switch* para la destrucción inmediata de pestañas comprometidas.

### 🧠 Motor de Amenazas Backend (FastAPI)
* **Inteligencia Global:** Integración nativa con la API de *Google Safe Browsing* para evaluar la reputación del dominio.
* **Heurística Typosquatting:** Implementación del algoritmo de distancia de *Levenshtein* para identificar suplantaciones de identidad (Phishing) contra entidades bancarias y tecnológicas (PayPal, bancos españoles, etc.).
* **Filtro Anti-Homógrafos (Punycode):** Bloqueo de ataques IDN que utilizan caracteres cirílicos camuflados (evaluación de cadenas `xn--`).
* **Data Masking (Privacidad):** Sanitización automatizada de URLs antes del almacenamiento (*Logging*), censurando correos electrónicos y parámetros sensibles (`token`, `password`, `session`) mediante Regex.

### 🏢 Gestión y Operaciones (SOC)
* **ChatOps en Tiempo Real:** Envío de *Webhooks* vía Telegram para alertar a los administradores de sistemas sobre incidentes críticos, reportando la IP del usuario comprometido y el vector de ataque.
* **Dashboard Ejecutivo HTML:** Generación y exportación de reportes dinámicos de inteligencia de amenazas con gráficas interactivas (Chart.js) inyectadas directamente desde el backend.
* **Hardening Anti-DoS:** Algoritmo *Rate Limiting* integrado en memoria para proteger los endpoints de la API frente a ataques de denegación de servicio.

---

## 🏗️ Arquitectura del Sistema

1. **Frontend (Chrome/JS):** Manipulación del DOM, intercepción de red y comunicación PNA (*Private Network Access*).
2. **Backend (FastAPI/Python):** Análisis forense de URLs, enmascaramiento de datos, lógica de *Rate Limit* y conexión con servicios de mensajería externos.
3. **Capa de Persistencia (SQLite):** Almacenamiento seguro y local de la telemetría depurada de los ataques y contadores de generación de contraseñas de alta entropía.

---

## 🚀 Instalación y Despliegue

### 1. Despliegue del Backend (Servidor SOC)
```bash
# Clonar el repositorio
git clone [https://github.com/xXMurallaXx/security-coach.git](https://github.com/xXMurallaXx/security-coach.git)
cd security-coach

# Configurar variables de entorno (Crear archivo .env)
# TELEGRAM_BOT_TOKEN=tu_token_aqui
# TELEGRAM_CHAT_ID=tu_chat_id_aqui

# Activar entorno virtual y arrancar
# Asegúrate de ejecutar el servidor desde la carpeta raíz o la carpeta backend según tu estructura
uvicorn backend.app.main:app --reload --port 8001