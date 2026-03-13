// --- MEMORIA DE CABECERAS POR PESTAÑA ---
const cabecerasSeguridad = {};

// --- ESCÁNER DE TRÁFICO DE RED ---
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        // Solo analizamos el esqueleto principal de la web, no imágenes ni anuncios
        if (details.type !== 'main_frame') return;

        const headersStatus = {
            hsts: false,         // Strict-Transport-Security
            csp: false,          // Content-Security-Policy
            xFrameOptions: false // X-Frame-Options
        };

        // Buscamos las cabeceras de seguridad
        if (details.responseHeaders) {
            for (let header of details.responseHeaders) {
                const name = header.name.toLowerCase();
                if (name === 'strict-transport-security') headersStatus.hsts = true;
                if (name === 'content-security-policy') headersStatus.csp = true;
                if (name === 'x-frame-options') headersStatus.xFrameOptions = true;
            }
        }

        // Guardamos el resultado asociado a esta pestaña específica
        cabecerasSeguridad[details.tabId] = headersStatus;
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);
// 1. ESCUCHADOR DE CARGA DE PÁGINA (Versión Robusta)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Solo actuamos cuando la página termina de cargar y tiene una URL válida
    if (changeInfo.status === "complete" && tab.url) {
        
        // Filtro de seguridad: ignorar páginas internas de Chrome y errores
        if (tab.url.startsWith('chrome://') || 
            tab.url.startsWith('chrome-error://') || 
            tab.url.startsWith('about:')) return;

        console.log("Analizando página: " + tab.url);

        // INYECTAMOS EL SENSOR (MutationObserver)
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => {
                let ultimaAlerta = 0;

const inyectarEscudoGenerador = () => {
    const passwordField = document.querySelector('input[type="password"]');
    
    // Si hay un campo y no lo hemos procesado aún...
    if (passwordField && !document.getElementById('sc-gen-btn')) {
        
        // --- CÓDIGO EXISTENTE DEL BOTÓN GENERADOR ---
        const btn = document.createElement('button');
        btn.id = 'sc-gen-btn';
        btn.innerHTML = '🛡️';
        btn.title = "Generar contraseña robusta (Security Coach)";
        btn.style.cssText = `margin-left: 5px; cursor: pointer; border: 1px solid #ccc; border-radius: 4px; background: #f0f0f0; padding: 2px 5px; font-size: 14px;`;
        
        btn.onclick = (e) => {
            e.preventDefault();
            btn.innerHTML = '⏳';
            chrome.runtime.sendMessage({ tipo: "PEDIR_PASSWORD" }, (response) => {
                if (response && response.password) {
                    passwordField.value = response.password;
                    passwordField.type = 'text';
                    btn.innerHTML = '✅';
                    setTimeout(() => { 
                        passwordField.type = 'password'; 
                        btn.innerHTML = '🛡️';
                    }, 3000);
                } else {
                    alert("Error: El Coach no respondió con una clave.");
                    btn.innerHTML = '❌';
                }
            });
        };
        passwordField.parentNode.insertBefore(btn, passwordField.nextSibling);

        // --- VIGILANTE DE CONTRASEÑAS (K-ANONYMITY EN EL FRONTEND) ---
        
        // 1. Función para crear el Hash SHA-1 nativo
        const generarHashSHA1 = async (texto) => {
            const buffer = new TextEncoder().encode(texto);
            const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        };

        // 2. Escuchamos cuando el usuario termina de escribir y sale del campo ('blur')
        passwordField.addEventListener('blur', async () => {
            const passwordMecaneada = passwordField.value;
            if (passwordMecaneada.length < 4) return; // Ignoramos si está vacío o es muy corta

            // Calculamos el hash y lo partimos
            const hashCompleto = await generarHashSHA1(passwordMecaneada);
            const prefijo = hashCompleto.substring(0, 5);
            const sufijo = hashCompleto.substring(5);

            // Le pedimos al background que consulte HIBP de forma segura
            chrome.runtime.sendMessage({ tipo: "COMPROBAR_HIBP", prefix: prefijo }, (response) => {
                if (response && response.listaPwned) {
                    // Verificamos si nuestro sufijo está en la lista negra que nos devolvió HIBP
                    const lineas = response.listaPwned.split('\n');
                    const estaFiltrada = lineas.some(linea => linea.split(':')[0] === sufijo);
                    
                    if (estaFiltrada) {
                        // Resaltamos el campo en rojo
                        passwordField.style.border = "3px solid #cc0000";
                        // Enviamos la orden de mostrar el banner
                        chrome.runtime.sendMessage({ 
                            tipo: "MOSTRAR_ALERTA_FRONTEND", 
                            mensaje: "¡CUIDADO! La contraseña que vas a usar ha sido filtrada por hackers en el pasado. Cámbiala por tu seguridad.",
                            gravedad: "CRITICAL"
                        });
                    } else {
                        // Pequeño feedback visual de que es segura (opcional)
                        passwordField.style.border = "2px solid #00cc00";
                        setTimeout(() => passwordField.style.border = "", 2000);
                    }
                }
            });
        });
    }
};

                const buscarYReportar = () => {
                    if (Date.now() - ultimaAlerta < 3000) return;
                    
                    const tienePassword = document.querySelector('input[type="password"]') !== null;
                    if (tienePassword) inyectarEscudoGenerador(); // <--- Llamamos al generador
                    
                    ultimaAlerta = Date.now();
                    chrome.runtime.sendMessage({ 
                        tipo: "VISITA_DETECTADA",
                        url: window.location.hostname,
                        fullUrl: window.location.href,
                        protocol: window.location.protocol,
                        has_sensitive_inputs: tienePassword
                    });
                };

                buscarYReportar();

                const observador = new MutationObserver((mutations) => {
                    for (let mutation of mutations) {
                        if (mutation.addedNodes.length > 0) {
                            const nodo = mutation.addedNodes[0];
                            if (nodo.id === 'security-coach-banner') return;
                        }
                    }
                    buscarYReportar();
                });

                observador.observe(document.body, { childList: true, subtree: true });
            }


        });

        // 3. LOGICA INICIAL PARA WEBS SIN PASSWORD (HTTP SIMPLE)
        // Esto asegura que si es HTTP pero NO tiene password, también se reporte una vez
        try {
            const url = new URL(tab.url);
            enviarEventoAlBackend(tab.url, url.protocol, false, tabId);
        } catch (e) { console.error("Error URL:", e); }
    }
});

// 2. OÍDO QUE ESCUCHA LOS MENSAJES DEL VIGILANTE
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.tipo === "VISITA_DETECTADA" && sender.tab) {
        enviarEventoAlBackend(request.fullUrl, request.protocol, request.has_sensitive_inputs, sender.tab.id);
    }
});

// 3. FUNCIÓN CENTRALIZADA PARA HABLAR CON EL BACKEND (EL CEREBRO)
function enviarEventoAlBackend(hostname, protocol, tienePassword, tabId) {
    // Rescatamos las cabeceras que guardó nuestro escáner (o asumimos que no hay si falla)
    const headersWeb = cabecerasSeguridad[tabId] || { hsts: false, csp: false, xFrameOptions: false };

    const eventData = {
        url: hostname,
        protocol: protocol,
        timestamp: new Date().toISOString(),
        has_sensitive_inputs: tienePassword,
        headers: headersWeb // Enviamos las cabeceras a Python
    };

    // Limpiamos la memoria para que el navegador no se sature
    delete cabecerasSeguridad[tabId];

    fetch("http://127.0.0.1:8001/event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(eventData)
    })
    .then(response => response.json())
    .then(data => {
        console.log("Respuesta del servidor:", data); // <-- ESTO ES CLAVE
        if (data.alert === true) {
            console.log("¡Alerta detectada! Intentando mostrar banner...");
            mostrarBannerEnPantalla(tabId, data.message, data.severity);
        } else {
            console.log("Servidor dice: Todo OK, sin alerta.");
        }
    })
    .catch(err => console.error("Error conexión Backend:", err));
}

// 4. FUNCIÓN PARA PINTAR EL BANNER (CON PRIORIDAD PARA CRÍTICOS)
function mostrarBannerEnPantalla(tabId, msg, severity) {
    chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (mensaje, gravedad) => {
            // 1. Si ya hay uno, lo quitamos para no amontonar
            const viejo = document.getElementById('security-coach-banner');
            if (viejo) viejo.remove();

            // 2. Colores según riesgo
            let bgColor = "#cc0000"; // Rojo (Peligro)
            if (gravedad === "HIGH") bgColor = "#ff8800"; // Naranja (Sospecha)
            if (gravedad === "MEDIUM") bgColor = "#444444"; // Gris (Inseguro)

            // 3. Crear el contenedor principal
            const div = document.createElement('div');
            div.id = 'security-coach-banner';
            
            // Estilos blindados
            div.style.cssText = `
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                width: 100% !important;
                min-height: 60px !important;
                background-color: ${bgColor} !important;
                color: white !important;
                z-index: 2147483647 !important;
                display: flex !important;
                align-items: center !important;
                justify-content: space-between !important;
                padding: 0 30px !important;
                font-family: sans-serif !important;
                font-weight: bold !important;
                box-shadow: 0 4px 10px rgba(0,0,0,0.5) !important;
                border-bottom: 3px solid rgba(255,255,255,0.3) !important;
            `;

            // 4. Contenido (Creamos elementos por separado para evitar XSS)
            const textoMensaje = document.createElement('div');
            textoMensaje.style.fontSize = "16px";
            // .textContent es la clave: neutraliza cualquier script malicioso
            textoMensaje.textContent = `🛡️ Security Coach: ${mensaje}`;

            const btnCerrar = document.createElement('button');
            btnCerrar.id = 'btn-cerrar-coach';
            btnCerrar.textContent = 'ENTENDIDO';
            btnCerrar.style.cssText = `
                background: white !important;
                color: black !important;
                border: none !important;
                padding: 8px 20px !important;
                font-weight: bold !important;
                cursor: pointer !important;
                border-radius: 5px !important;
                min-width: 120px !important;
            `;

            div.appendChild(textoMensaje);
            div.appendChild(btnCerrar);

            // 5. Inyectar y Activar el botón
            document.body.appendChild(div);
                        // --- NUEVO: BLOQUEO DE SEGURIDAD ---
            // Si el riesgo es CRÍTICO, buscamos el input de password y lo bloqueamos
            const passwordInput = document.querySelector('input[type="password"]');
            if (gravedad === "CRITICAL" && passwordInput) {
                passwordInput.disabled = true; // Bloquea el campo
                passwordInput.style.backgroundColor = "#ffebeb"; // Lo pone en un tono rojizo suave
                passwordInput.title = "CAMPO BLOQUEADO POR SEGURIDAD: Revisa el banner superior.";
            }
            // -----------------------------------
            const btn = div.querySelector('#btn-cerrar-coach');
            
            btn.addEventListener('click', () => {
                // 1. Buscamos si hay un campo de password bloqueado
                const passwordInput = document.querySelector('input[type="password"]');
                
                // 2. Si existe, lo liberamos
                if (passwordInput) {
                    passwordInput.disabled = false;
                    passwordInput.style.backgroundColor = ""; 
                }

                // 3. BORRAR EL BANNER (Esta línea es la que hace que desaparezca)
                div.remove();
            });

        },
        args: [msg, severity]
    });
}
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.tipo === "PEDIR_PASSWORD") {
        fetch("http://127.0.0.1:8001/generate-password")
            .then(r => r.json())
            .then(data => sendResponse({ password: data.password }))
            .catch(err => {
                console.error("Error backend:", err);
                sendResponse({ password: null });
            });
        return true; // Mantiene el canal abierto para la respuesta asíncrona
    }
    if (request.tipo === "COMPROBAR_HIBP") {
        fetch(`https://api.pwnedpasswords.com/range/${request.prefix}`)
            .then(r => r.text()) // HIBP devuelve texto plano, no JSON
            .then(texto => sendResponse({ listaPwned: texto }))
            .catch(err => {
                console.error("Error consultando HIBP:", err);
                sendResponse({ listaPwned: null });
            });
        return true; // Obligatorio para respuestas asíncronas con fetch
    }

    // --- MOSTRAR ALERTA DESDE EL VIGILANTE DE CONTRASEÑAS ---
    if (request.tipo === "MOSTRAR_ALERTA_FRONTEND" && sender.tab) {
        mostrarBannerEnPantalla(sender.tab.id, request.mensaje, request.gravedad);
    }
});




