# Relay local con inspección de HAR

## Pedido

Cargar HAR del usuario, usar el servidor local como relay hacia Ganamos y los proveedores presentes en su tráfico, y examinar peticiones y respuestas completas. Publicar el código en `Shisetsu-Code/Relay`, actualmente vacío. El usuario autorizó el uso de sus credenciales; los HAR y las credenciales no se publican.

## Decisiones de implementación

Se usa Python 3.12+ y mitmproxy/mitmweb 12.3.1. El motor existente ofrece proxy HTTP/HTTPS, WebSocket, interfaz de inspección y replay manual. Evita implementar TLS y WebSocket desde cero. Una API propia limitada a doInit no satisface este pedido; un proxy inverso por sí solo puede dejar fuera URLs absolutas del cliente. Por eso el modo normal es un proxy explícito para el navegador, con opción adicional de proxy inverso para clientes locales con endpoint configurable.

El proxy y la interfaz se vinculan únicamente a 127.0.0.1. Se conserva la autenticación nativa aleatoria de mitmweb. Se crea un directorio local de datos/CA y una captura por ejecución; nada de ello se sube a GitHub. El relay no filtra campos de juego, sustituye tokens ni renueva credenciales automáticamente. Cargar un HAR no envía sus solicitudes. El replay se activa sobre una petición elegida por el operador.

## Fidelidad e importación

La transmisión en vivo conserva la semántica HTTP y los cuerpos; el transporte puede cambiar TLS, versión HTTP y encabezados de conexión. No se promete una captura de paquetes idéntica. El importador de HAR de la versión fijada necesita una adaptación: soportar cuerpos request con extensión base64, mantener encabezados duplicados, y no inventar un cuerpo cuando falta. Un request cuyo cuerpo no pueda reconstruirse se puede inspeccionar, pero se marca con raw_content=None para que el replay nativo lo rechace. La adaptación cubre la carga inicial y la carga por la interfaz web. Se documentan los cambios necesarios en respuestas históricas que el HAR guarda descomprimidas.

## Inspección

La GUI nativa permite ver/editar headers y cuerpos, filtrar, reenviar manualmente, duplicar y exportar. Un addon pasivo anota observaciones concretas: errores HTTP, HTTP sin TLS, credenciales en query, cambio de dominio frente a los HAR importados, redirects externos y peticiones lentas. Las observaciones no afirman por sí solas que exista una intrusión. No se modifica request/response ni se bloquean acciones del usuario por ser distintas de doInit.

Los flujos completos quedan en archivos .mitm locales. Un informe JSONL opcional registra sólo método, host, ruta saneada, estado, tiempo y códigos de observación; no valores de credenciales, queries ni cuerpos. Un exportador offline permite extraer los bytes raw capturados de un flujo para comparar sin descompresión automática.

## Validación

Pruebas unitarias del importador, launcher y addon. Pruebas de integración con un upstream controlado en loopback: headers duplicados, query y cuerpo binario, respuesta comprimida, errores y replay. Ninguna prueba automática llama a Ganamos, consume saldo ni reenvía HAR reales. Se comprobará la importación offline del HAR de Ganamos. CI Linux/Windows probará el repositorio. La conexión real previa recibió HTTP 403, por lo que no se declarará una sesión real funcionando sin nueva evidencia.

## Fuera de alcance

Una pasarela pública multiusuario, ocultar credenciales a quien controla el navegador de inspección, renovar sesiones privadas automáticamente, reproducir fingerprints TLS del navegador o corregir un rechazo HTTP 403 del sitio.
