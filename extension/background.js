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
                
                // NUEVO MÓDULO: PROTECCIÓN FINANCIERA (ZERO-TRUST + LUHN)
                
                // 1. Motor Matemático de Luhn
                function validarLuhn(numeroTarjeta) {
                    let valor = numeroTarjeta.replace(/\D/g, '');
                    if (valor.length < 13 || valor.length > 19) return false;
                    let suma = 0;
                    let multiplicarPorDos = false;
                    for (let i = valor.length - 1; i >= 0; i--) {
                        let digito = parseInt(valor.charAt(i), 10);
                        if (multiplicarPorDos) {
                            digito *= 2;
                            if (digito > 9) digito -= 9;
                        }
                        suma += digito;
                        multiplicarPorDos = !multiplicarPorDos;
                    }
                    return (suma % 10) === 0;
                }

                // 2. Inteligencia de Contexto y Lista Blanca
                const regexFinanciero = /(cvv|cvc|tarjeta|caducidad|credit card|mastercard|visa)/i;
                const PASARELAS_CONFIABLES = ["redsys.es", "stripe.com", "paypal.com", "amazon.es"];

                function esDominioConfiable(hostnameActual) {
                    return PASARELAS_CONFIABLES.some(dominioSeguro => hostnameActual.endsWith(dominioSeguro));
                }

                // 3. El Vigilante del Teclado (Event Listener)
                document.addEventListener('keyup', function(evento) {
                    let elemento = evento.target;
                    // Solo vigilamos cajas de texto o números
                    if (elemento.tagName !== 'INPUT' || (elemento.type !== 'text' && elemento.type !== 'number' && elemento.type !== 'tel')) return;

                    let textoIntroducido = elemento.value;
                    let soloNumeros = textoIntroducido.replace(/\D/g, '');

                    // Filtro de rendimiento: Solo activamos Luhn si hay 13 o más números
                    if (soloNumeros.length >= 13 && validarLuhn(textoIntroducido)) {
                        
                        // Buscamos palabras clave en el entorno del input
                        let textoContexto = document.body.innerText + elemento.placeholder + elemento.name;
                        
                        if (regexFinanciero.test(textoContexto)) {
                            let dominioActual = window.location.hostname;
                            
                            // Comprobamos la Lista Blanca
                            if (!esDominioConfiable(dominioActual)) {
                                
                                // ¡ATAQUE DETECTADO! Bloqueo preventivo físico
                                elemento.value = ""; // Vaciamos la caja
                                elemento.disabled = true; // La bloqueamos
                                elemento.style.border = "3px solid #cc0000"; // Borde rojo
                                elemento.style.backgroundColor = "#ffebeb"; // Fondo rojizo
                                
                                // Lanzamos tu banner de alerta nativo
                                chrome.runtime.sendMessage({ 
                                    tipo: "MOSTRAR_ALERTA_FRONTEND", 
                                    mensaje: "¡BLOQUEO PREVENTIVO! Estás introduciendo una tarjeta en un dominio no autorizado (" + dominioActual + ").",
                                    gravedad: "CRITICAL"
                                });
                            }
                        }
                    }
                });
                // NUEVO MÓDULO: ESCUDO ANTI-EXFILTRACIÓN Y DLP (MEMORIA)
                // 1. Bloqueo de Portapapeles (Mitigación de secuestro de memoria)
                document.addEventListener('copy', (evento) => {
                    let elemento = evento.target;
                    // Si están intentando copiar de un campo de contraseña o de la tarjeta...
                    if (elemento.tagName === 'INPUT' && (elemento.type === 'password' || validarLuhn(elemento.value))) {
                        evento.preventDefault(); // Cortamos la acción física
                        console.warn("🛡️ Security Coach: Intento de copia de datos sensibles bloqueado por políticas DLP.");
                    }
                });                
            }
        });
        // NUEVO MÓDULO: API HOOKING (NATIVO MANIFEST V3)
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            world: "MAIN", // <--- ESTA ES LA LLAVE MAESTRA QUE EVITA EL ERROR ROJO
            func: () => {
                if (!window.edrHookActivado) {
                    window.edrHookActivado = true;
                    const fetchOriginal = window.fetch;
                    
                    console.log("🛡️ [EDR] Interceptor de Red activado en el Main World.");

                    window.fetch = async function(...args) {
                        const urlDestino = args[0];
                        const opciones = args[1];

                        // Si la petición lleva datos (POST)...
                        if (opciones && opciones.body && typeof opciones.body === 'string') {
                            const passwordInputs = document.querySelectorAll('input[type="password"]');
                            let exfiltracionDetectada = false;

                            passwordInputs.forEach(input => {
                                // Si la contraseña tiene más de 3 letras y va en el paquete...
                                if (input.value.length > 3 && opciones.body.includes(input.value)) {
                                    exfiltracionDetectada = true;
                                }
                            });

                            // Bloqueamos si cazamos la exfiltración
                            if (exfiltracionDetectada && !urlDestino.includes('127.0.0.1')) {
                                console.error("🛑 BLOQUEO EDR: Intento de exfiltración hacia: " + urlDestino);
                                
                                const alertaDLP = document.createElement('div');
                                alertaDLP.style.cssText = "position:fixed; top:60px; left:0; width:100%; background:#8b0000; color:white; text-align:center; padding:10px; z-index:999999; font-weight:bold;";
                                alertaDLP.innerText = "🚨 ALERTA DLP: Se ha bloqueado un intento de robo de credenciales en segundo plano.";
                                document.body.appendChild(alertaDLP);
                                setTimeout(() => alertaDLP.remove(), 5000);

                                return Promise.reject(new Error("Conexión bloqueada por Security Coach (DLP)"));
                            }
                        }
                        // Si todo es normal, continúa el tráfico
                        return fetchOriginal.apply(this, args);
                    };
                }
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
                box-sizing: border-box !important;
                min-height: 60px !important;
                background-color: ${bgColor} !important;
                color: white !important;
                z-index: 2147483647 !important;
                display: flex !important;
                align-items: center !important;
                justify-content: space-between !important;
                padding: 0 40px 0 20px !important;
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
                margin-right: 10px !important;
                white-space: nowrap !important;
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
                // 1. Buscamos TODOS los inputs de la página (contraseñas y textos de tarjeta)
                const todosLosInputs = document.querySelectorAll('input');
                
                // 2. Los recorremos y liberamos los que nuestro EDR haya bloqueado
                todosLosInputs.forEach(input => {
                    if (input.disabled) {
                        input.disabled = false; // Le devolvemos el control al usuario
                        input.style.backgroundColor = ""; // Quitamos el fondo rojizo
                        input.style.border = ""; // Quitamos el borde rojo de alerta
                    }
                });

                // 3. BORRAR EL BANNER (Desaparece visualmente)
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
// --- MÓDULO EDR: INTERCEPTOR DE DESCARGAS Y HASHING ---

// Función criptográfica para calcular el SHA-256 de un archivo en memoria
async function calculateSHA256(arrayBuffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// El Vigilante: Salta cuando se inicia cualquier descarga
chrome.downloads.onCreated.addListener(async (downloadItem) => {
    // Evitamos analizar archivos temporales o descargas internas del propio navegador
    if (downloadItem.state !== "in_progress" || downloadItem.url.startsWith("blob:") || downloadItem.url.startsWith("data:")) {
        return;
    }

    console.log(`[EDR] 🚨 Nueva descarga detectada: ${downloadItem.filename}`);
    
    // 1. CONGELAMOS LA DESCARGA INSTANTÁNEAMENTE
    chrome.downloads.pause(downloadItem.id, async () => {
        console.log(`[EDR] ⏸️ Descarga pausada. Iniciando análisis heurístico...`);
        
        try {
            // 2. Extraemos el archivo a la memoria (RAM) para analizarlo
            const response = await fetch(downloadItem.url);
            const arrayBuffer = await response.arrayBuffer();
            
            // 3. Calculamos el Hash SHA-256 militar
            const fileHash = await calculateSHA256(arrayBuffer);
            console.log(`[EDR] 🧬 Hash calculado: ${fileHash}`);

            // 4. Enviamos el Hash al SOC (Tu servidor Python)
            // Ajusta el puerto si tu servidor usa uno distinto al 8001
            const socResponse = await fetch("http://127.0.0.1:8001/check_download", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    filename: downloadItem.filename || "archivo_desconocido",
                    file_hash: fileHash
                })
            });

            const result = await socResponse.json();
            
            // 5. EJECUTAMOS LA ORDEN DEL SERVIDOR
            if (result.action === "BLOCK") {
                console.warn(`[EDR] 🛑 MALWARE CONFIRMADO: ${result.reason}`);
                chrome.downloads.cancel(downloadItem.id);
                
                // Opcional: Lanzar una notificación visual al empleado
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png", // Asegúrate de tener un icon.png en tu extensión
                    title: "Security Coach: BLOQUEO CRÍTICO",
                    message: `La descarga de ${downloadItem.filename} ha sido cancelada. Es malware reportado.`
                });
            } else {
                console.log(`[EDR] ✅ Archivo limpio. Reanudando descarga.`);
                chrome.downloads.resume(downloadItem.id);
            }

        } catch (error) {
            console.error("[EDR] ❌ Error durante el análisis del archivo:", error);
            // Si hay un error (ej. archivo muy grande o red caída), por precaución en corporativo dejamos pasar.
            chrome.downloads.resume(downloadItem.id);
        }
    });
});



