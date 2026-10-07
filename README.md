# 🔎 FingerPrint Lab

Laboratorio didáctico de **browser fingerprinting** (huella digital del navegador) para clases de ciberseguridad.
Inspirado en Panopticlick / Cover Your Tracks (EFF) y AmIUnique.

Los estudiantes abren una página desde su celular o portátil, el navegador se escanea en vivo con ~30 técnicas
reales y el docente ve en un panel cuántas huellas son únicas, qué atributos identifican más y cuántos
estudiantes fueron **reconocidos aunque borraran cookies o usaran modo incógnito**.

## Requisitos

- Python 3.8 o superior. **No necesita instalar nada** (solo librería estándar).
- Docente y estudiantes en la misma red Wi-Fi.
- Internet solo para el código QR del panel; la auditoría de metadatos también requiere que el equipo del docente pueda acceder al sitio autorizado.

## Uso

```bash
python3 app.py              # puerto 8000, abre el panel docente
python3 app.py --port 9000  # otro puerto
python3 app.py --no-browser
```

| Dirección | Para quién |
|---|---|
| `http://localhost:8000/panel` | Docente: QR, estadísticas en vivo, entropía por atributo |
| `http://<IP-del-docente>:8000/` | Estudiantes: escáner, teoría y experimentos |
| `http://<IP-del-docente>:8000/?auto` | Igual, pero inicia el escaneo automáticamente |

> En macOS/Windows puede aparecer un aviso del firewall: permite conexiones entrantes a Python.

## Qué incluye

- **Escáner** animado tipo terminal: User-Agent, canvas, WebGL, audio, fuentes, zona horaria, idiomas,
  hardware, preferencias de accesibilidad, cabeceras HTTP (fingerprinting pasivo)…
  Cada tarjeta explica *qué es*, *por qué identifica* y *cómo protegerse*, con bits de entropía en el aula
  vs. referencia mundial.
- **Reconocimiento sin cookies**: el servidor compara la huella con visitas anteriores y lo muestra
  frente al identificador por cookie.
- **Aprende**: 6 conceptos clave, calculadora interactiva de entropía (33 bits = población mundial),
  tabla de defensas y marco legal (GDPR, Ley 1581 de 2012).
- **Experimentos** guiados: incógnito, borrar cookies, zoom, VPN, otro navegador, idioma, Brave/Tor,
  sala de cómputo idéntica.
- **Metadatos web y confidencialidad**: rastrea recursos del mismo dominio desde enlaces HTML, `robots.txt`,
  `sitemap.xml`, referencias estáticas de JavaScript y una lista corta de rutas educativas. Analiza PDF, Office,
  OpenDocument, imágenes, audio, JSON, CSV, XML, configuración, mapas de fuentes y ZIP. Clasifica señales de
  identidad, finanzas, operación, infraestructura y credenciales; presenta en pantalla todos los valores de metadatos que reconoce,
  incluidos autor y ubicación. Las detecciones de datos estructurados se agrupan por categoría y campo.
- **Informe CSV redactado**: exporta archivo de origen, categoría, severidad, conteo, explicación y mitigación,
  sin incluir los valores sensibles encontrados.
- **Análisis de archivos**: permite subir cualquier formato hasta 20 MB. Extrae propiedades conocidas de PDF,
  documentos Office/OpenDocument, imágenes JPEG/PNG/TIFF/WebP y audio MP3/WAV; resume datos sensibles en
  JSON/CSV/configuración y contenido ZIP acotado. Los demás muestran tipo, tamaño y SHA-256. Se procesa en
  memoria, sin almacenar ni ejecutar el archivo.
- **Panel docente** en vivo con QR, % de huellas únicas, reconocidos sin cookie y ranking de entropía de Shannon.

La auditoría está limitada a 50 páginas, 500 archivos, 5 MB por archivo y 3 minutos por recorrido; prueba hasta
16 rutas comunes y procesa como máximo 100 rutas citadas por `robots.txt`, sitemaps o JavaScript.
No usa buscadores externos, no ejecuta JavaScript ni macros, no inicia sesión y rechaza direcciones locales o
privadas y redirecciones a otros dominios. En ZIP solo lista y lee miembros pequeños en memoria con límites; no
extrae archivos al disco. En PDF lee propiedades Info y XMP visibles; algunos metadatos dentro de streams
comprimidos no se detectan. Los resultados se muestran en pantalla y no se guardan. Úsala solo en sitios propios
o con autorización.

La carga de archivos es independiente del rastreo web: requiere confirmar permiso para enviar el archivo al
servidor del laboratorio. El tamaño máximo es 20 MB por archivo. Las propiedades que se muestran dependen del
formato; un formato no reconocido solo presenta identificación básica, no una inspección completa del contenido.

## Guion sugerido (45 min)

1. Proyecta el panel y pide a todos escanear con el QR (5 min).
2. Comenta el % de huellas únicas y el ranking de atributos (10 min).
3. Todos abren el sitio en **incógnito** y escanean otra vez → sube el contador 🚨 (5 min).
4. Pestaña **Aprende**: entropía y calculadora (10 min).
5. **Experimentos** en grupos y discusión de defensas y ética (15 min).

## Privacidad

Los datos del fingerprinting se guardan solo en `data/visits.json` en el equipo del docente. El botón
«Reiniciar datos de la clase» (solo disponible desde el propio equipo del docente) los borra. El análisis
de metadatos no guarda los documentos ni sus resultados. Los valores de metadatos de identidad y ubicación
se muestran directamente en pantalla. Las detecciones dentro de datos estructurados se agrupan con conteos y
nombres de campos; el informe CSV sigue redactado y no incluye valores personales.

## Estructura

```
app.py              servidor HTTP + API (huella, entropía y análisis de metadatos)
web/index.html      página del estudiante
web/panel.html      panel del docente
web/js/collectors.js  técnicas de fingerprinting
web/js/catalog.js     explicaciones didácticas de cada atributo
web/js/scanner.js     escáner, teoría y experimentos
web/js/metadata.js    carga, resultados y explicaciones de metadatos
web/js/panel.js       panel en vivo
web/css/style.css     estilos (tema oscuro/claro)
```
