# Relay

[![Relay tests](https://github.com/Shisetsu-Code/Relay/actions/workflows/tests.yml/badge.svg)](https://github.com/Shisetsu-Code/Relay/actions/workflows/tests.yml)

Relay local para **cargar HAR, reenviar tráfico HTTP/HTTPS y examinar peticiones y respuestas completas**, con interfaz web de mitmweb.

El navegador o cliente se conecta al proxy local; el proxy realiza las solicitudes al destino original y devuelve sus respuestas. Se conservan los cuerpos del tráfico, incluidas respuestas binarias y comprimidas. El observador añade anotaciones de diagnóstico sin filtrar campos, reemplazar credenciales ni modificar el contenido.

## Inicio en Windows

Requiere **Python 3.12 o posterior**. La dependencia está fijada en `mitmproxy==12.3.1` porque usamos sus interfaces de importación.

```powershell
git clone https://github.com/Shisetsu-Code/Relay.git
cd Relay
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe relay.py
```

También podés ejecutar `start-windows.bat` después de instalar las dependencias.

| Servicio | Dirección |
|---|---|
| Proxy HTTP y HTTPS | `127.0.0.1:8080` |
| Panel de inspección | `http://127.0.0.1:8081/` |

El panel se abre con un **token local aleatorio**. Si no se abre, copiá de la terminal el enlace completo que incluye `?token=...`. Ese token autentica el panel; no es una credencial de Ganamos. Ambos servicios escuchan sólo en tu computadora.

En Linux/macOS:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python relay.py
```

## Cargar un HAR

En el panel, usá **File → Open** y seleccioná tu archivo `.har`. También podés cargarlo al arrancar:

```powershell
.venv\Scripts\python.exe relay.py --har "C:\capturas\ganamos.har"
```

**Importar no envía las solicitudes.** El panel muestra la captura histórica. Para enviar una petición al servidor, seleccioná el flujo y usá **Replay**. Usá **Duplicate** antes si querés conservar la respuesta histórica para compararla: el replay actualiza la respuesta del flujo seleccionado.

La vista permite ver el método, URL, encabezados, cookies, cuerpo enviado, código de estado, cuerpo recibido y tiempos. Los encabezados y cuerpos se pueden editar explícitamente desde el panel. No se inicia un replay masivo ni una renovación automática de sesiones.

El cargador web de la versión fijada admite solicitudes de carga de hasta 4 GiB; los HAR de 110/149 MB entran en ese límite. El consumo de RAM es mayor que el tamaño del archivo porque se conservan el JSON y los flujos. **Open reemplaza la vista actual**; guardá o exportá lo que quieras conservar antes de cargar otro archivo. Una importación inválida puede quedar parcial.

## Pasar tráfico real por el relay

1. Iniciá Relay.
2. En la configuración de red del navegador de prueba, elegí proxy manual y configurá **HTTP y HTTPS en `127.0.0.1`, puerto `8080`**.
3. Desde ese navegador, abrí [http://mitm.it](http://mitm.it) e instalá la CA local de mitmproxy en el perfil de prueba. Hace falta para inspeccionar HTTPS. Relay mantiene habilitada la verificación del certificado del servidor remoto.
4. Abrí Ganamos o ejecutá tu cliente local. Las solicitudes y respuestas aparecen en el panel mientras se reenvían al destino.
5. Para terminar, cerrá Relay con `Ctrl+C` y quitá el proxy del navegador.

Se usa la sesión que envía el navegador o la solicitud concreta que elegiste del HAR. El programa **no mezcla cookies de distintos flujos ni sustituye automáticamente tokens vencidos**. Si una credencial del HAR venció, el servidor puede rechazar el replay.

Los clientes que ignoran el proxy del sistema deben configurarlo explícitamente. Ejemplo con cURL:

```powershell
curl.exe --proxy http://127.0.0.1:8080 --cacert .\data\ca\mitmproxy-ca-cert.pem https://ganamosonline.com/
```

La CA y su clave se generan localmente dentro de `data/ca/`. No se incluye una CA compartida ni se instala automáticamente en el sistema.

## Servidor local con destino fijo

Para un juego o cliente que permita cambiar la URL de su API, podés activar un listener de proxy inverso adicional:

```powershell
.venv\Scripts\python.exe relay.py --reverse https://ganamosonline.com --reverse-port 8082
```

Una solicitud a `http://127.0.0.1:8082/pragmatic/game/link?...` se dirige al mismo path/query en `https://ganamosonline.com`. El proxy normal sigue disponible en `8080` y la inspección en `8081`.

En modo inverso el motor adapta `Host` al destino elegido. No reescribe HTML, URLs absolutas, cookies de dominio, `Origin`, `Referer`, CSP o CORS. Un juego con varios dominios puede llamar por fuera de ese listener; para inspeccionar su tráfico completo, configurá el proxy normal en el navegador. No se reemplazan destinos del HAR por el destino inverso durante su importación.

## Qué significa conservar la solicitud

| Elemento | Comportamiento |
|---|---|
| Método, URL y query | Se conservan en el proxy normal. |
| Cookies y autorización | Se reenvían al destino del flujo y se pueden inspeccionar localmente. |
| Cuerpo HTTP capturado en vivo | Se conserva como bytes, incluida su compresión. |
| Encabezados duplicados | Se conservan como pares, sin reducirlos a un diccionario. |
| TLS, HTTP/2, framing y headers de conexión | El motor establece otra conexión; no son una copia de paquetes o de la huella TLS del navegador. |
| HAR incompleto | Se indica qué falta; no se inventa un cuerpo para reenviarlo. |

El adaptador de HAR corrige la lectura de cuerpos request con la extensión `postData.encoding=base64` y distingue un cuerpo ausente de un cuerpo vacío. Conserva las cabeceras ordinarias duplicadas. Los pseudoencabezados HTTP/2 se representan en los campos de protocolo correspondientes; si contradicen la URL o el método, no se habilita el replay.

Al importar un cuerpo conocido que no trae cabeceras de longitud o transferencia, se agrega `Content-Length` cuando hace falta para reenviarlo correctamente sobre HTTP/1. Esta normalización queda anotada en el flujo y no cambia los bytes del cuerpo. Se usa la representación de versión HTTP esperada por el motor, para que el replay de una captura HTTP/2 pueda negociar otra conexión correctamente.

Las entradas `data:`, `blob:`, `file:` y `about:` son recursos locales o embebidos, no solicitudes a un servidor. El lector las omite de la vista de tráfico y registra un conteo por esquema; siguen intactas en tu HAR original. En la captura Ganamos usada para verificar el importador había 50 entradas `data:` de este tipo.

Cuando faltan bytes, hay un multipart incompleto o el HAR no permite determinar la representación de un cuerpo request comprimido, el flujo queda visible con una advertencia y **el motor rechaza su replay por contenido ausente**. Los cuerpos de texto se reconstruyen con el charset conocido; esto no demuestra igualdad con bytes de red que el HAR no guardó.

Las respuestas históricas de un HAR pueden estar descomprimidas. Su representación importada se identifica como tal y puede necesitar normalizar `Content-Encoding`/`Content-Length`. Esta adaptación no modifica las respuestas del tráfico en vivo. El exportador raw descrito abajo permite extraer los bytes que realmente quedaron capturados.

## Observaciones y filtros

El addon añade códigos a los comentarios del flujo cuando observa:

- HTTP 401, 403 o errores 5xx.
- HTTP sin TLS.
- Nombres de parámetros de credenciales en la URL.
- Un host fuera de los HAR cargados como referencia.
- Redirección a otro dominio.
- Respuesta de más de 5 segundos o error de transporte.

Son señales para revisar. Un dominio nuevo o un 403 no identifica por sí solo una intrusión. Sin un HAR de referencia no se etiqueta un dominio como nuevo.

Filtros útiles del panel:

```text
~d ganamosonline.com
~m POST
~u gameService
~c 403
~e
~websocket
```

WebSocket se reenvía y sus mensajes se pueden inspeccionar. El motor no reproduce una conversación WebSocket completa mediante Replay; tampoco guarda PING/PONG como mensajes de aplicación.

## Capturas e informes locales

Cada ejecución crea un directorio dentro de `data/sessions/`:

- `traffic.mitm`: flujos completos capturados, con cuerpos, encabezados y credenciales que existan en el tráfico.
- `audit.jsonl`: observaciones resumidas sin cuerpos, queries, valores de credenciales ni segmentos originales de rutas. La ruta se representa con una plantilla; la original sigue visible en la GUI y la captura completa.

La descarga normal de un cuerpo desde mitmweb puede descomprimirlo. Para obtener los bytes `raw_content` de la captura:

```powershell
.venv\Scripts\python.exe -m relay_inspector.export_raw "data\sessions\TU_SESION\traffic.mitm" --index 0 --output "exports\flujo-0"
```

`--index` empieza en cero; también se puede seleccionar con `--flow-id`. El exportador escribe cuerpos `.bin` y un manifiesto con método, URL, cabeceras ordenadas en base64, tamaños y SHA-256 de cuerpos. **Ese export contiene los datos originales**, por eso debe permanecer local igual que el HAR y `traffic.mitm`.

`.gitignore` excluye los directorios de datos/capturas/exportación, HAR, flujos, informes de sesión y claves. El repositorio incluye únicamente código y datos sintéticos de prueba.

## Opciones

```text
--har ARCHIVO         Cargar una captura al iniciar, sin enviarla
--proxy-port 8080     Puerto del proxy normal
--web-port 8081       Puerto del panel
--no-browser         No abrir automáticamente el navegador
--data-dir RUTA       Directorio local de datos y CA
--reverse URL         Agregar un relay hacia un destino fijo
--reverse-port 8082   Puerto del listener inverso
--upstream-ca ARCHIVO CA adicional/de confianza para un upstream de laboratorio
```

Relay no carga `~/.mitmproxy/config.yaml` ni ejecuta scripts, replay o sustituciones provenientes de configuraciones previas. La autenticación del panel permanece activa; no publica los servicios en la LAN.

## Pruebas

```powershell
.venv\Scripts\python.exe -m unittest discover -v
```

La suite usa datos sintéticos y upstreams en loopback. Comprueba importación, cuerpos ausentes/base64, ausencia de modificaciones por el observador, exportación binaria y el motor real con HTTP, HTTPS, WebSocket y replay explícito. CI ejecuta las pruebas en Linux y Windows. No envía peticiones a Ganamos ni ejecuta operaciones sobre cuentas reales.

Verificación local de esta entrega: **65 pruebas aprobadas**, incluidas siete de integración con el motor real. El HAR Ganamos de 377 entradas se importó sin red: **327 entradas de red**, 50 recursos `data:` omitidos explícitamente y 15 solicitudes cuyo cuerpo no se pudo reconstruir para replay. La solicitud `doInit` sí conservó su cuerpo y pasó la comprobación nativa de replay, sin enviarse. Los informes están en [`docs/verification.json`](docs/verification.json) y [`docs/har-import-verification.json`](docs/har-import-verification.json).

La solicitud autenticada de la prueba anterior recibió HTTP 403 antes del lanzamiento del juego. Este proyecto no afirma resolver ese rechazo ni haber validado una sesión real de Ganamos: el resultado depende de la sesión y de la respuesta que obtengas al usarlo localmente.

## Referencias

- [mitmproxy 12.3.1](https://pypi.org/project/mitmproxy/12.3.1/)
- [Modos de proxy](https://docs.mitmproxy.org/stable/concepts/modes/)
- [Certificados](https://docs.mitmproxy.org/stable/concepts/certificates/)
- [Filtros](https://docs.mitmproxy.org/stable/concepts/filters/)
- [Protocolos y límites](https://docs.mitmproxy.org/stable/concepts/protocols/)
- [Importador original de la versión fijada](https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/mitmproxy/io/har.py)
