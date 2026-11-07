# MediWebScan

Suite de reconocimiento web escrita en Python por **medicineh**. Combina descubrimiento de subdominios, comprobación HTTP, identificación de tecnologías y módulos opcionales, con informes TXT, JSON y HTML.

Este README describe la versión corregida de `MediWebScan.py`, incluida su opción `--debug`.

## Instalación

Guarda `MediWebScan.py` en una carpeta y ejecuta desde ella:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests dnspython
python MediWebScan.py --help
```

`requests` es obligatorio. `dnspython` permite resolver DNS desde Python; algunas funciones pueden utilizar herramientas externas como alternativa. El programa está orientado a entornos Linux.

## Inicio rápido

```bash
# Ejecución básica
python MediWebScan.py example.com

# Diagnósticos de herramientas externas
python MediWebScan.py example.com --debug

# Directorios, crawling y URLs históricas
python MediWebScan.py example.com -D -C -P

# Todos los módulos
python MediWebScan.py example.com -A
```

Sustituye `example.com` por el dominio de tu evaluación autorizada.

También se acepta una URL HTTP/HTTPS. Se extrae su dominio: `https://example.com/ruta` se convierte en `example.com`; la ruta no limita el análisis. No se admiten credenciales ni puertos en el objetivo.

La ejecución básica ya realiza solicitudes activas: además de fuentes pasivas, incluye fuerza bruta DNS cuando dispone de diccionario y resolutor, comprobación HTTP, detección WAF/CDN, cabeceras y tecnologías. No es un modo exclusivamente pasivo.

## Opciones

| Opción | Función |
| --- | --- |
| `-h`, `--help` | Mostrar ayuda. |
| `-A`, `--all` | Activar todos los módulos opcionales. |
| `-p`, `--ports` | Escaneo de puertos y servicios con Nmap. |
| `-v`, `--vuln` | Scripts `vuln` de Nmap; prepara el escaneo de puertos si es necesario. |
| `-D`, `--dirs` | Enumeración de directorios y archivos. |
| `-C`, `--crawl` | Descubrimiento de enlaces y endpoints. |
| `-N`, `--nuclei` | Ejecutar Nuclei. |
| `-S`, `--screenshots` | Capturar páginas con herramientas externas. |
| `-T`, `--takeover` | Buscar indicios de subdomain takeover. |
| `-P`, `--params` | Consultar URLs históricas y extraer parámetros. |
| `-w`, `--wordlist` | Ruta del diccionario DNS. |
| `--dir-wordlist` | Ruta del diccionario de directorios. |
| `--depth` | Profundidad de enumeración de directorios; predeterminado: `2`. |
| `-t`, `--threads` | Concurrencia solicitada; predeterminado: `30`. |
| `--no-color` | Desactivar colores propios de la consola. |
| `--stealth` | Activar pausas aleatorias en las solicitudes Python compatibles. |
| `--delay` | Pausa máxima en segundos; con `--stealth`, predeterminado: `2.0`. |
| `--debug` | Mostrar comandos externos, tiempos límite y diagnósticos disponibles. |

`--threads` y `--depth` deben ser mayores que cero. `--delay` debe ser finito y no negativo; solo tiene efecto junto con `--stealth`.

## Diccionarios

Rutas predeterminadas:

```text
DNS:         /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
Directorios: /usr/share/seclists/Discovery/Web-Content/common.txt
```

Puedes utilizar tus propios archivos, con una entrada por línea:

```bash
python MediWebScan.py example.com -D \
  -w ./dns.txt \
  --dir-wordlist ./directorios.txt \
  --depth 2 -t 10
```

Si no encuentra un diccionario de directorios, busca alternativas de SecLists y dirb en rutas conocidas. Si no encuentra ninguno, omite esa fase. Si no dispone de diccionario DNS o resolutor compatible, omite la fuerza bruta DNS.

## Herramientas opcionales

Instala las que necesites y comprueba que sus ejecutables estén en `PATH`.

| Función | Herramientas o alternativa |
| --- | --- |
| Subdominios pasivos | crt.sh mediante Python; `subfinder`, `amass`, `assetfinder` si están disponibles. |
| Fuerza bruta DNS | `gobuster` o `dnspython`. |
| Comprobación HTTP | `httpx` de ProjectDiscovery o `requests`. |
| WAF/CDN | `wafw00f` y comprobación propia. |
| Tecnologías | `whatweb` y fingerprint propio. |
| Puertos y vulnerabilidades Nmap | `nmap`. |
| Resolución CNAME | `dnspython` o `dig`. |
| Directorios | `feroxbuster`, `gobuster`, `dirb` o Python, en ese orden. |
| Crawling | `katana` y extracción propia de enlaces. |
| URLs históricas | `waybackurls`, `gau` o API de Wayback si faltan ambos. |
| Plantillas de vulnerabilidades | `nuclei`. |
| Capturas | `gowitness`, `eyewitness`, `cutycapt` o `wkhtmltoimage`. |

Las interfaces de estas herramientas pueden variar según su versión. `httpx` de ProjectDiscovery es distinto del cliente HTTP de Python del mismo nombre. Las opciones de profundidad y concurrencia no se aplican de forma idéntica a todos los motores; por ejemplo, la integración de dirb no recibe `--depth`.

## Resultados

Cada ejecución crea una carpeta en el **directorio de trabajo actual**:

```text
recon_example.com_FECHA_HORA_MICROSEGUNDOS/
├── report.txt
├── report.json
├── report.html
├── subs_all.txt
├── subs_alive.txt
├── waf.txt
├── headers.txt
├── tech.txt
├── takeover.txt
├── ips.txt
├── nmap.txt / nmap.xml
├── nmap_vuln.txt / nmap_vuln.xml
├── dirs.txt
├── dirs_per_host/
├── crawl.txt
├── params.txt
├── params_juicy.txt
├── nuclei.txt
├── nuclei.jsonl
└── screenshots/
    └── gallery.html
```

Los archivos de módulos opcionales solo aparecen cuando la fase se ejecuta y produce el archivo correspondiente. La galería depende de la herramienta de capturas utilizada. `params_juicy.txt` solo se genera si encuentra URLs con las extensiones seleccionadas.

Abre `report.html` en el navegador para consultar el informe. `report.json` contiene el resumen y los resultados de las fases como texto; no es un inventario completamente estructurado de hallazgos. La exportación de Nuclei utiliza JSONL, con un objeto JSON por línea.

## Depuración

```bash
python MediWebScan.py example.com --debug --no-color > debug.log 2>&1
```

| Síntoma | Comprobación |
| --- | --- |
| Mensaje solicitando `requests` | Activa el entorno virtual e instala las dependencias en él. |
| Una herramienta no se ejecuta | Comprueba su presencia con `command -v nombre` y consulta su ayuda. |
| Error de argumentos de una herramienta | Revisa `debug.log` y la versión instalada. |
| No se enumeran directorios | Comprueba el diccionario y los mensajes del motor utilizado. |
| No aparecen capturas | Comprueba que exista una herramienta compatible y sus requisitos de navegador o entorno gráfico. |
| Resultados parciales | Algunas herramientas tienen tiempos límite; revisa los avisos de timeout. |
| No aparecen subdominios adicionales | Las fuentes públicas pueden fallar o no tener datos; el dominio principal se conserva. |

`--debug` facilita el diagnóstico de procesos externos, pero no elimina todos los bloques que capturan excepciones ni garantiza una traza de cada fallo HTTP o DNS.

## Comportamiento y límites

- El modo `--stealth` introduce pausas por solicitud Python, entre el 30 % y el 100 % del máximo configurado. No impone un límite global de peticiones ni controla automáticamente las herramientas externas. El User-Agent ya se elige aleatoriamente en los helpers HTTP habituales.
- El crawler y la recopilación histórica filtran URLs por el dominio objetivo y sus subdominios. Esto no constituye un control global de alcance: otras fases pueden seguir redirecciones, y Nmap trabaja sobre las IP resueltas, que pueden ser compartidas.
- Las comprobaciones HTTP propias desactivan la verificación de certificados TLS.
- Las firmas de tecnologías, WAF y takeover son heurísticas. Un candidato a takeover requiere validación; un error de conexión no demuestra vulnerabilidad.
- La enumeración Python de directorios no filtra automáticamente todas las páginas de error que responden con código `200`.
- La ausencia de hallazgos no demuestra que un sitio carezca de vulnerabilidades.

## Cambios de la versión corregida

- Añadida la opción `--debug` y mensajes sobre errores de procesos externos.
- Conservación de salida parcial cuando un proceso alcanza su tiempo límite.
- Validación del objetivo, hilos, profundidad y demora.
- Inclusión del dominio principal aunque las fuentes pasivas no devuelvan resultados.
- Corrección del argumento de exportación JSONL de Nuclei.
- Desactivación explícita de la lista negra de estados de Gobuster al utilizar la lista positiva.
- Filtrado del crawler por dominio completo, evitando mezclar objetivos distintos bajo sufijos como `co.uk`.
- Resolución de enlaces relativos respecto a la URL final de la respuesta.
- Filtrado de URLs históricas y conservación de parámetros con valores vacíos.
- Los errores de conexión ya no se presentan como takeover confirmado.

La versión se verificó con compilación Python, ayuda de consola y ocho pruebas de regresión con respuestas simuladas. No se ha validado una ejecución completa contra un objetivo real ni todas las versiones de herramientas externas.

## Autor

**medicineh** · [Medicineh-Web-Scanner](https://github.com/Medicineh/Medicineh-Web-Scanner)
