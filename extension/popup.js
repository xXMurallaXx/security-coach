document.addEventListener('DOMContentLoaded', function() {
    
    fetch("http://127.0.0.1:8001/stats") 
        .then(response => {
            if (!response.ok) throw new Error('Error en la red');
            return response.json();
        })
        .then(data => {
            console.log("Datos recibidos:", data); 

            // 1. Asegurar que los valores sean números (evita el ERR)
            const critico = parseInt(data.CRITICAL) || 0;
            const alto = parseInt(data.HIGH) || 0;
            const medio = parseInt(data.MEDIUM) || 0;
            const claves = parseInt(data.passwords_generated) || 0;
            
            // Si el backend no envía el total, lo calculamos nosotros
            const totalCalculado = data.total || (critico + alto + medio);

            // 2. Actualizar textos en el HTML
            document.getElementById('contador').innerText = totalCalculado;
            document.getElementById('critical-count').innerText = critico;
            document.getElementById('high-count').innerText = alto;
            document.getElementById('medium-count').innerText = medio;
            document.getElementById('claves-generadas').innerText = claves;

            // 3. Crear la gráfica
            const canvas = document.getElementById('vulnerabilitiesChart');
            if (canvas) {
            // Si ya existe una gráfica previa, la destruimos para que no parpadee al recargar
                if (window.miGrafica) { window.miGrafica.destroy(); }

                const ctx = canvas.getContext('2d');
                window.miGrafica = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Crítico', 'Alto', 'Medio'],
                        datasets: [{
                            data: [critico, alto, medio],
                            backgroundColor: ['#cc0000', '#ff8800', '#666666'], 
                            borderWidth: 0,
                            hoverOffset: 4,
                            weight: 1
                        }]
                    },
                    options: {
                        cutout: '80%', 
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }, // Ocultamos la leyenda para ahorrar espacio
                            tooltip: { enabled: true }  // Que se vea el número al pasar el ratón
                        }
                    }
                });
            }

        })
        .catch(error => {
            console.error("Error cargando estadísticas:", error);
            // Solo actualizamos el contador principal si hay error
            const contador = document.getElementById('contador');
            if (contador) contador.innerText = "--";
            document.getElementById('status-text').innerText = "● Servidor Offline";
            document.getElementById('status-text').style.color = "red";
        });

    // --- LÓGICA DEL BOTÓN DEL PÁNICO ---
    const killSwitchBtn = document.getElementById('kill-switch-btn');
    if (killSwitchBtn) {
        killSwitchBtn.addEventListener('click', () => {
            // 1. Preguntamos a Chrome cuál es la pestaña activa en la ventana actual
            chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
                if (tabs && tabs.length > 0) {
                    const currentTabId = tabs[0].id;
                    // 2. Cerramos esa pestaña instantáneamente
                    chrome.tabs.remove(currentTabId, () => {
                        console.log("Pestaña cerrada por seguridad.");
                        window.close(); // Cerramos el popup
                    });
                }
            });
        });
    }
// --- LÓGICA DE EXPORTACIÓN DE REPORTE ---
    const btnExport = document.getElementById('btn-export');
    if (btnExport) {
        btnExport.addEventListener('click', () => {
            btnExport.innerText = "⏳ Generando...";
            
            // Hacemos la petición a nuestro nuevo endpoint
            fetch("http://127.0.0.1:8001/export")
                .then(res => {
                    if (!res.ok) throw new Error("Error en el servidor");
                    return res.blob(); // Convertimos la respuesta en un "archivo" (blob)
                })
                .then(blob => {
                    // Magia de JavaScript para forzar la descarga en el navegador
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = "Security_Coach_Report.html";
                    document.body.appendChild(a);
                    a.click(); // Simulamos que el usuario hace clic en el enlace oculto
                    a.remove();
                    window.URL.revokeObjectURL(url);
                    
                    btnExport.innerText = "✅ Descargado";
                    setTimeout(() => btnExport.innerText = "📥 Exportar Reporte de Incidentes", 3000);
                })
                .catch(err => {
                    console.error(err);
                    btnExport.innerText = "❌ Error";
                    setTimeout(() => btnExport.innerText = "📥 Exportar Reporte de Incidentes", 3000);
                });
        });
    }
});
