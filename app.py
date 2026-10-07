#!/usr/bin/env python3
"""
FingerPrint Lab — laboratorio didáctico de *browser fingerprinting*.

Levanta un servidor web local (solo librería estándar de Python) al que los
estudiantes se conectan desde su navegador. La página escanea el navegador,
calcula qué tan identificable es y el servidor demuestra cómo se puede
reconocer a un visitante aunque borre sus cookies o use modo incógnito.

Uso:
    python3 app.py                 # puerto 8000, abre el navegador
    python3 app.py --port 9000     # otro puerto
    python3 app.py --no-browser    # no abrir el navegador automáticamente

Rutas:
    /         escáner para estudiantes
    /panel    panel en vivo para el docente
    /api/metadata-scan  análisis didáctico de recursos públicos autorizados
    /api/metadata-upload análisis en memoria de un archivo autorizado
"""

import argparse
import csv
import email.policy
import hashlib
import http.client
import ipaddress
import json
import math
import re
import socket
import struct
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict, deque
from email.parser import BytesParser
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO, StringIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit
from urllib.request import HTTPHandler, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
DATA_FILE = ROOT / "data" / "visits.json"

# Atributos "estables": no cambian al borrar cookies, abrir incógnito o
# redimensionar la ventana. Con ellos se calcula el ID de huella del visitante.
STABLE_KEYS = [
    "ua", "platform", "vendor", "languages", "timezone", "intl", "screen",
    "colorDepth", "hardwareConcurrency", "deviceMemory", "touch", "canvas",
    "webglVendor", "webglParams", "audio", "fonts", "math", "plugins",
]

MAX_VALUE_LEN = 4000

# Límites del ejercicio de metadatos. El rastreador no usa buscadores externos,
# no inicia sesión y solo lee recursos del dominio indicado.
SCAN_MAX_PAGES = 50
SCAN_MAX_FILES = 500
SCAN_MAX_PATH_PROBES = 16
SCAN_MAX_INDEXED_PATHS = 100
SCAN_MAX_FETCHES = SCAN_MAX_PAGES + SCAN_MAX_FILES + SCAN_MAX_PATH_PROBES + SCAN_MAX_INDEXED_PATHS + 2
SCAN_MAX_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 250
MAX_ARCHIVE_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 10 * 1024 * 1024
SCAN_TIMEOUT = 3
SCAN_DEADLINE = 180
SCAN_EXTENSIONS = {
    ".pdf": "PDF",
    ".docx": "Word",
    ".xlsx": "Excel",
    ".pptx": "PowerPoint",
    ".odt": "OpenDocument Text",
    ".ods": "OpenDocument Spreadsheet",
    ".odp": "OpenDocument Presentation",
    ".jpg": "Imagen JPEG",
    ".jpeg": "Imagen JPEG",
    ".png": "Imagen PNG",
    ".tif": "Imagen TIFF",
    ".tiff": "Imagen TIFF",
    ".webp": "Imagen WebP",
    ".wav": "Audio WAV",
    ".mp3": "Audio MP3",
    ".json": "Datos JSON",
    ".csv": "Datos CSV",
    ".xml": "Datos XML",
    ".txt": "Texto",
    ".ini": "Configuración INI",
    ".conf": "Configuración",
    ".env": "Configuración de entorno",
    ".bak": "Respaldo",
    ".backup": "Respaldo",
    ".sql": "Volcado SQL",
    ".js": "JavaScript estático",
    ".mjs": "JavaScript estático",
    ".map": "Mapa de fuentes",
    ".md": "Documento Markdown",
    ".log": "Registro de texto",
    ".yaml": "Configuración YAML",
    ".yml": "Configuración YAML",
    ".toml": "Configuración TOML",
    ".properties": "Configuración",
    ".htaccess": "Configuración del servidor web",
    ".zip": "Archivo ZIP",
}

SCAN_PATH_HINTS = (
    "robots.txt", "sitemap.xml", "humans.txt", ".well-known/security.txt",
    "admin/", "backup/", "config/", "private/", "old/", "dev/", "intranet/",
    "api/", "uploads/", "documents/", "descargas/", "downloads/",
)


class ScanError(ValueError):
    """Error seguro y legible para una solicitud de auditoría web."""


class UploadTooLarge(ScanError):
    """El archivo o el formulario supera el máximo permitido."""


class LinkCollector(HTMLParser):
    """Recoge enlaces, recursos estáticos y metadatos sin ejecutar JavaScript."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.metadata = {}
        self.in_title = False
        self.title_parts = []
        self.text_parts = []
        self.text_size = 0
        self.observed_pairs = []
        self.base_href = ""

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)
        target = attrs.get("href") if tag in ("a", "link") else attrs.get("src")
        if tag in {"a", "link", "script", "img", "source", "video", "audio", "iframe"} and target:
            if len(self.links) < 1000:
                self.links.append(target.strip())
        if tag == "a" and target:
            if target.lower().startswith("mailto:"):
                self.observed_pairs.append(("email", target[7:].split("?", 1)[0][:200]))
            elif target.lower().startswith("tel:"):
                self.observed_pairs.append(("phone", target[4:][:80]))
        if tag == "title":
            self.in_title = True
        if tag == "base" and attrs.get("href"):
            self.base_href = attrs["href"].strip()
        if tag == "meta":
            key = (attrs.get("name") or attrs.get("property") or "").strip().lower()
            value = (attrs.get("content") or "").strip()
            meta_names = {
                "author": "creator", "description": "description", "keywords": "keywords",
                "generator": "generator", "application-name": "application", "copyright": "copyright",
                "og:title": "title", "og:site_name": "company", "article:published_time": "creation-date",
                "article:modified_time": "modified", "twitter:creator": "creator",
            }
            mapped = meta_names.get(key)
            if mapped and value:
                self.metadata.setdefault(mapped, value[:500])

    def handle_data(self, data):
        if data.strip() and self.text_size < 1_000_000:
            piece = data[:1_000_000 - self.text_size]
            self.text_parts.append(piece)
            self.text_size += len(piece)
        if self.in_title and data.strip():
            self.title_parts.append(data.strip())

    def handle_comment(self, data):
        if data.strip() and len(self.observed_pairs) < 2000:
            self.observed_pairs.extend(_text_pairs(data[:100_000]))

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False
            title = " ".join(self.title_parts).strip()
            if title:
                self.metadata.setdefault("title", title[:500])


def _public_host(host):
    """Rechaza nombres locales y destinos que resuelvan a redes no públicas."""
    if not host or host.lower().rstrip(".") in {"localhost", "localhost.localdomain"}:
        raise ScanError("Indica el dominio público del sitio que tienes autorización para auditar.")
    if host.lower().endswith((".local", ".internal", ".localhost")):
        raise ScanError("Por seguridad, no se pueden escanear nombres de red local.")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise ScanError("Escribe el nombre de dominio del sitio, no una dirección IP.")

    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except OSError as exc:
        raise ScanError("No se pudo resolver el dominio. Revisa la dirección e inténtalo otra vez.") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ScanError("El dominio resuelve a una dirección privada o reservada y no se escaneará.")
    return sorted(addresses)[0]


def _normalize_scan_url(value, expected_host=None, resolve=True):
    value = str(value or "").strip()
    if not value or len(value) > 2048:
        raise ScanError("Escribe una dirección web válida (máximo 2048 caracteres).")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise ScanError("La dirección web no tiene un formato válido.") from exc
    if scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
        raise ScanError("Solo se aceptan direcciones HTTP o HTTPS sin usuario ni contraseña.")
    if port not in (None, 80, 443) or (port == 80 and scheme == "https") or (port == 443 and scheme == "http"):
        raise ScanError("Solo se permiten los puertos web estándar (80 y 443).")
    if expected_host and host != expected_host:
        raise ScanError("El sitio redirigió a otro dominio; se detuvo el escaneo.")
    if resolve:
        _public_host(host)
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, "")), host


class SameHostRedirectHandler(HTTPRedirectHandler):
    """Permite redirecciones solo al mismo dominio público."""

    def __init__(self, expected_host):
        super().__init__()
        self.expected_host = expected_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        normalized, _ = _normalize_scan_url(urljoin(req.full_url, newurl), self.expected_host)
        return super().redirect_request(req, fp, code, msg, headers, normalized)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Conecta a la IP pública validada, sin volver a resolver el dominio."""

    def __init__(self, host, address, **kwargs):
        super().__init__(host, **kwargs)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Mantiene el nombre TLS del sitio y conecta a la IP ya validada."""

    def __init__(self, host, address, context=None, **kwargs):
        super().__init__(host, context=context, **kwargs)
        self.address = address

    def connect(self):
        raw_socket = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


class PinnedHTTPHandler(HTTPHandler):
    """Handler HTTP que evita una segunda resolución DNS al conectar."""

    def __init__(self, address):
        self.address = address
        super().__init__()

    def http_open(self, request):
        return self.do_open(lambda host, **kwargs: PinnedHTTPConnection(host, self.address, **kwargs), request)


class PinnedHTTPSHandler(HTTPSHandler):
    """Handler HTTPS que conserva el nombre TLS al usar una IP validada."""

    def __init__(self, address):
        self.address = address
        super().__init__()

    def https_open(self, request):
        return self.do_open(
            lambda host, **kwargs: PinnedHTTPSConnection(
                host, self.address, context=self._context, **kwargs
            ),
            request,
        )


def _fetch_public_url(url, expected_host):
    normalized, host = _normalize_scan_url(url, expected_host)
    address = _public_host(host)
    opener = build_opener(
        ProxyHandler({}),
        PinnedHTTPHandler(address),
        PinnedHTTPSHandler(address),
        SameHostRedirectHandler(expected_host),
    )
    request = Request(normalized, headers={
        "User-Agent": "FingerPrintLab-MetadataClass/1.0",
        "Accept": "text/html,application/pdf,application/json,text/csv,application/xml,text/plain,application/zip,image/*,audio/*,application/vnd.openxmlformats-officedocument,application/vnd.oasis.opendocument,*/*;q=0.2",
    })
    try:
        with opener.open(request, timeout=SCAN_TIMEOUT) as response:
            final_url, _ = _normalize_scan_url(response.geturl(), expected_host)
            length = response.headers.get("Content-Length")
            if length and int(length) > SCAN_MAX_BYTES:
                raise ScanError("El recurso supera el límite de 5 MB y se omitió.")
            content = response.read(SCAN_MAX_BYTES + 1)
            if len(content) > SCAN_MAX_BYTES:
                raise ScanError("El recurso supera el límite de 5 MB y se omitió.")
            return final_url, content, response.headers.get_content_type()
    except ScanError:
        raise
    except HTTPError as exc:
        raise ScanError(f"El servidor respondió HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, socket.timeout, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise ScanError("El servidor tardó demasiado en responder.") from exc
        raise ScanError("No se pudo leer el recurso (puede requerir acceso o no estar disponible).") from exc


def _safe_xml(data):
    if len(data) > 1_000_000 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return None
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        return None


def _xml_values(root):
    if root is None:
        return {}
    values = defaultdict(list)
    for node in root.iter():
        name = node.tag.rsplit("}", 1)[-1].lower()
        text = " ".join((node.text or "").split())
        if name in {
            "title", "subject", "creator", "description", "keywords", "lastmodifiedby",
            "created", "modified", "revision", "application", "appversion", "company",
            "manager", "template", "total_time", "initial-creator", "creation-date",
            "date", "createdate", "modifydate", "generator", "creatortool",
            "editing-cycles", "editing-duration", "totaltime",
        }:
            if not text:
                text = " ".join(" ".join((part.text or "").split()) for part in node.iter()).strip()
            if text:
                values[name].append(text[:500])
    return {key: ", ".join(dict.fromkeys(items))[:1000] for key, items in values.items()}


def _pdf_decode_string(raw):
    if raw.startswith(b"<") and raw.endswith(b">"):
        try:
            data = bytes.fromhex(raw[1:-1].decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            return ""
    else:
        data = raw[1:-1]
        data = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8)]), data)
        data = re.sub(rb"\\([()\\])", rb"\1", data)
        data = data.replace(b"\\n", b"\n").replace(b"\\r", b"\r").replace(b"\\t", b"\t")
    try:
        value = data.decode("utf-16") if data.startswith((b"\xfe\xff", b"\xff\xfe")) else data.decode("latin-1")
    except UnicodeDecodeError:
        return ""
    return " ".join(value.split())[:1000]


def _pdf_metadata(data):
    fields = {}
    key_names = {
        "Title": "title", "Subject": "subject", "Author": "creator", "Creator": "application",
        "Producer": "generator", "Keywords": "keywords", "CreationDate": "creation-date",
        "ModDate": "modified",
    }
    # El diccionario Info suele estar en claro. No se descomprimen streams PDF.
    for match in re.finditer(rb"\b\d+\s+\d+\s+obj\b(.*?)\bendobj\b", data, re.S):
        body = match.group(1)
        found = {}
        for pdf_key, key in key_names.items():
            value_match = re.search(rb"/" + pdf_key.encode("ascii") + rb"\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>)", body, re.S)
            if value_match:
                value = _pdf_decode_string(value_match.group(1))
                if value:
                    found[key] = value
        if found:
            fields.update(found)
            break

    xmp_start = data.find(b"<x:xmpmeta")
    xmp_end = data.find(b"</x:xmpmeta>", xmp_start)
    if xmp_start >= 0 and xmp_end >= 0:
        root = _safe_xml(data[xmp_start:xmp_end + len(b"</x:xmpmeta>")])
        fields.update({k: v for k, v in _xml_values(root).items() if k not in fields})
    return fields


def extract_document_metadata(data, extension):
    """Extrae propiedades comunes sin ejecutar macros ni abrir el documento."""
    if extension == ".pdf":
        return _pdf_metadata(data), "PDF (diccionario Info y XMP visibles; no descomprime streams)"

    fields = {}
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            names = set(archive.namelist())
            for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml", "meta.xml"):
                if name not in names:
                    continue
                info = archive.getinfo(name)
                if info.file_size > 1_000_000:
                    continue
                with archive.open(name) as metadata_file:
                    metadata_xml = metadata_file.read(1_000_001)
                if len(metadata_xml) <= 1_000_000:
                    root = _safe_xml(metadata_xml)
                    fields.update(_xml_values(root))
                    if name == "docProps/custom.xml" and root is not None:
                        for node in root.iter():
                            prop_name = node.attrib.get("name", "").strip()
                            value = " ".join((child.text or "").strip() for child in node.iter()).strip()
                            if prop_name and value:
                                fields[f"custom:{prop_name[:80]}"] = value[:500]
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return {}, "Paquete Office/OpenDocument no legible"
    return fields, "Propiedades del paquete Office/OpenDocument"


RISK_RULES = (
    ("Credenciales", "Alto", re.compile(r"password|passwd|secret|token|api.?key|private.?key|credential|deprecated.?key", re.I),
     "Puede facilitar acceso no autorizado si el dato sigue activo.", "Revocar y rotar el secreto; retirarlo del cliente y del historial público."),
    ("Identidad y contacto", "Alto", re.compile(r"name|nombre|author|creator|artist|owner|serial|email|correo|phone|telefono|celular|document|cedula|passport|employee|emergency.?contact|internal.?user", re.I),
     "Puede identificar, contactar o ayudar a suplantar a empleados y terceros.", "Reducir campos, restringir acceso y publicar solo datos de contacto institucionales."),
    ("Ubicación", "Alto", re.compile(r"gps|latitude|longitude|location|coordinates", re.I),
     "Puede revelar la ubicación exacta de una persona, equipo o actividad.", "Eliminar coordenadas y revisar EXIF/XMP antes de publicar imágenes."),
    ("Finanzas", "Alto", re.compile(r"salary|salario|bank|account|cuenta|invoice|factura|amount|monto|payment|pago|cost.?center|contract|contrato", re.I),
     "Puede exponer remuneraciones, referencias bancarias, pagos o condiciones comerciales.", "Retirar el archivo público y limitar la consulta por rol; cambiar o invalidar referencias expuestas."),
    ("Operación", "Medio", re.compile(r"shift|turno|radio|shutdown|parada|maintenance|mantenimiento|dispatch|production|produccion|asset|activo|field|campo|schedule|ventana", re.I),
     "Puede revelar horarios, activos, rutinas o ventanas de operación.", "Publicar información agregada y retrasada; restringir horarios y detalles de activos."),
    ("Infraestructura", "Medio", re.compile(r"host|server|erp|database|internal.?db|vpn|sftp|intranet|endpoint|environment|mapclienttoken|legacy.?api", re.I),
     "Puede revelar nombres de sistemas internos, rutas o componentes que orientan un ataque.", "Eliminar referencias internas del cliente y separar servicios públicos de internos."),
)
EMAIL_VALUE_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
INTERNAL_HOST_RE = re.compile(r"\b[a-z0-9][a-z0-9.-]*\.(?:ap\.local|internal|local)\b", re.I)
SECRET_VALUE_RE = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b")


def _sensitive_findings(pairs):
    """Resume señales de confidencialidad sin devolver los valores encontrados."""
    groups = {}

    def add(category, severity, field, explanation, mitigation):
        group = groups.setdefault(category, {
            "category": category, "severity": severity, "count": 0, "fields": set(),
            "explanation": explanation, "mitigation": mitigation,
        })
        group["count"] += 1
        if field:
            group["fields"].add(str(field)[:100])

    for key, value in pairs[:10000]:
        field = str(key or "contenido")[:100]
        text = str(value or "")[:5000]
        if not text.strip():
            continue
        matched = {}
        for category, severity, pattern, explanation, mitigation in RISK_RULES:
            if pattern.search(field):
                matched[category] = (severity, explanation, mitigation)
        if EMAIL_VALUE_RE.search(text):
            matched["Identidad y contacto"] = (
                "Alto", "Puede identificar o facilitar contacto dirigido a personas.",
                "Retirar correos personales y publicar buzones funcionales cuando sean necesarios.")
        if INTERNAL_HOST_RE.search(text):
            matched["Infraestructura"] = (
                "Medio", "Puede revelar nombres de sistemas o redes que deberían ser internos.",
                "Eliminar hosts internos de recursos públicos y revisar DNS y configuración.")
        if SECRET_VALUE_RE.search(text):
            matched["Credenciales"] = (
                "Alto", "El valor parece una clave o token con formato reconocible.",
                "Revocar y rotar el secreto; retirarlo del cliente y del historial público.")
        for category, (severity, explanation, mitigation) in matched.items():
            add(category, severity, field, explanation, mitigation)
    severity_order = {"Alto": 0, "Medio": 1, "Bajo": 2}
    return [
        {**finding, "fields": sorted(finding["fields"])[:20]}
        for finding in sorted(groups.values(), key=lambda item: (severity_order[item["severity"]], item["category"]))
    ]


def _flatten_data(value, key="", depth=0, pairs=None):
    if pairs is None:
        pairs = []
    if len(pairs) >= 10000 or depth > 12:
        return pairs
    if isinstance(value, dict):
        for child_key, child in list(value.items())[:1000]:
            _flatten_data(child, str(child_key), depth + 1, pairs)
    elif isinstance(value, list):
        for child in value[:1000]:
            _flatten_data(child, key or "registro", depth + 1, pairs)
    elif value is not None:
        text = str(value)
        pairs.append((key or "valor", text[:5000]))
        if isinstance(value, str) and len(value) > 5000:
            pairs.extend((f"{key}.{child_key}", child_value)
                         for child_key, child_value in _text_pairs(value[5000:1_000_000])[:2000])
    return pairs


def _largest_record_list(value, depth=0):
    if depth > 12:
        return 0
    largest = len(value) if isinstance(value, list) and value and all(isinstance(row, dict) for row in value[:20]) else 0
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for child in list(children)[:1000]:
        largest = max(largest, _largest_record_list(child, depth + 1))
    return largest


def _text_pairs(text):
    pairs = []
    assignment = re.compile(r"^\s*[\"']?([A-Za-z][A-Za-z0-9_. /-]{1,80})[\"']?\s*[:=]\s*[\"']?([^#\r\n]{1,1000})", re.M)
    for match in assignment.finditer(text[:1_000_000]):
        key = match.group(1).strip().strip("'\"")
        value = match.group(2).strip().rstrip(",;\"'")
        if key and value:
            pairs.append((key, value))
        if len(pairs) >= 5000:
            break
    for match in re.finditer(r"\b(?:password|passwd|secret|token|api.?key|salary|bank.?account|employee.?id|gps|internal.?host)\b", text[:1_000_000], re.I):
        pairs.append((match.group(0), "campo detectado en texto"))
        if len(pairs) >= 10000:
            break
    return pairs


def _structured_content(data, extension):
    """Devuelve esquema y pares de campos para CSV/JSON/XML/configuración."""
    text = (data[:1_000_000] if extension == ".xml" else data).decode("utf-8-sig", errors="replace")
    metadata = {"lineCount": str(text.count("\n") + (1 if text else 0)), "sizeBytes": str(len(data))}
    pairs = []
    record_count = 0
    if extension == ".csv":
        lines = text.splitlines()
        if len(lines) > 1 and re.search(r"aviso|sint[eé]tic|entrenamiento|demostraci[oó]n", lines[0], re.I):
            lines = lines[1:]
        csv_text = "\n".join(lines)
        try:
            dialect = csv.Sniffer().sniff(csv_text[:8192], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        rows = csv.DictReader(StringIO(csv_text, newline=""), dialect=dialect)
        fieldnames = [str(name)[:100] for name in (rows.fieldnames or [])[:100] if name]
        for index, row in enumerate(rows):
            if index >= 5000:
                break
            record_count += 1
            for key in fieldnames:
                value = row.get(key)
                if value:
                    pairs.append((key, value[:5000]))
        metadata["recordCount"] = str(record_count)
        metadata["fields"] = ", ".join(fieldnames[:50]) or "No se reconocieron encabezados"
    elif extension in {".json", ".map"}:
        try:
            value = json.loads(text)
            pairs = _flatten_data(value)
            record_count = _largest_record_list(value)
            metadata["recordCount"] = str(record_count)
            metadata["fields"] = ", ".join(sorted({key for key, _ in pairs})[:50]) or "Sin campos"
            if extension == ".map" and isinstance(value, dict):
                metadata["sourceCount"] = str(len(value.get("sources", [])))
                metadata["embeddedSources"] = str(sum(bool(item) for item in value.get("sourcesContent", [])))
        except (json.JSONDecodeError, RecursionError, ValueError):
            pairs = _text_pairs(text)
            metadata["parseStatus"] = "JSON no legible"
    elif extension == ".xml":
        root = _safe_xml(data[:1_000_000])
        if root is not None:
            for node in root.iter():
                value = " ".join((node.text or "").split())
                if value:
                    pairs.append((node.tag.rsplit("}", 1)[-1], value[:1000]))
                    if len(pairs) >= 10000:
                        break
            metadata["fields"] = ", ".join(sorted({key for key, _ in pairs})[:50]) or "Sin campos"
        else:
            pairs = _text_pairs(text)
            metadata["parseStatus"] = "XML no legible"
        if len(data) > 1_000_000:
            metadata["parseStatus"] = "XML limitado a 1 MB por seguridad"
    else:
        pairs = _text_pairs(text)
        metadata["fields"] = ", ".join(sorted({key for key, _ in pairs})[:50]) or "Sin pares nombre/valor"
    return metadata, pairs


def _archive_name_findings(names):
    pairs = []
    for name in names[:MAX_ARCHIVE_ENTRIES]:
        lowered = name.lower()
        if any(marker in lowered for marker in ("payroll", "nomina", "salary", "ordenes_pago", "bank", "private/", "directorio-interno")):
            pairs.append(("salary bank account payroll private employee", "nombre de archivo sensible"))
        if any(marker in lowered for marker in (".env", "secret", "credential", "application.ini", "config/")):
            pairs.append(("secret credential configuration", "nombre de archivo de configuración"))
        if any(marker in lowered for marker in ("dump.sql", ".sql", "database", "db_")):
            pairs.append(("database internal_db", "nombre de archivo de base de datos"))
    return _sensitive_findings(pairs)


def _resource_documents(data, extension, name, url, archive_depth=0):
    """Analiza un recurso estático y, para ZIP, miembros acotados en memoria."""
    metadata = {}
    pairs = []
    method = "Se identificó el tipo, tamaño y SHA-256; no se ejecutó el recurso."
    if extension == ".pdf":
        metadata, method = _pdf_metadata(data), "Propiedades Info/XMP visibles en PDF; no se ejecutan acciones ni se abre el documento."
        pairs = list(metadata.items())
    elif extension in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}:
        metadata, method = extract_document_metadata(data, extension)
        pairs = list(metadata.items())
    elif extension in {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"}:
        kind = {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".tif": "TIFF", ".tiff": "TIFF", ".webp": "WebP"}[extension]
        signatures = {"JPEG": data.startswith(b"\xff\xd8\xff"), "PNG": data.startswith(b"\x89PNG\r\n\x1a\n"),
                      "TIFF": data.startswith((b"II*\0", b"MM\0*")), "WebP": data.startswith(b"RIFF") and data[8:12] == b"WEBP"}
        metadata = _image_metadata(data, kind) if signatures[kind] else {}
        method = f"Metadatos EXIF/XMP reconocidos en {kind}; no se decodificó la imagen."
        pairs = list(metadata.items())
    elif extension == ".mp3":
        metadata = AudioTagCollector.mp3(data)
        method = "Etiquetas ID3 reconocidas; no se reproduce el audio."
        pairs = list(metadata.items())
    elif extension == ".wav":
        metadata = _wav_metadata(data)
        method = "Etiquetas INFO de WAV; no se reproduce el audio."
        pairs = list(metadata.items())
    elif extension == ".zip":
        metadata = {"sha256": hashlib.sha256(data).hexdigest(), "compressedBytes": str(len(data))}
        method = "Se listan y clasifican nombres; miembros compatibles se leen en memoria con límites."
    else:
        metadata, pairs = _structured_content(data, extension)
        method = "Se analizaron campos y patrones sin mostrar valores personales ni ejecutar contenido."

    if extension == ".zip":
        try:
            with zipfile.ZipFile(BytesIO(data)) as archive:
                entries = [item for item in archive.infolist() if not item.is_dir()]
                metadata["entryCount"] = str(len(entries))
                metadata["uncompressedBytes"] = str(sum(item.file_size for item in entries))
                findings = _archive_name_findings([item.filename for item in entries])
                documents = [{"url": url, "name": name, "format": "Archivo ZIP", "method": method,
                              "metadata": metadata, "findings": findings,
                              "fileInfo": {"sizeBytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "type": "Archivo ZIP"}}]
                if len(entries) > MAX_ARCHIVE_ENTRIES:
                    documents[0]["findings"].append({"category": "Alcance del análisis", "severity": "Medio", "count": len(entries) - MAX_ARCHIVE_ENTRIES,
                        "fields": [], "explanation": "El ZIP contiene más entradas que el límite didáctico.",
                        "mitigation": "Revisar el archivo en un entorno aislado con límites de descompresión."})
                if archive_depth == 0:
                    total_read = 0
                    supported_entries = 0
                    skipped_entries = max(0, len(entries) - MAX_ARCHIVE_ENTRIES)
                    for item in entries[:MAX_ARCHIVE_ENTRIES]:
                        member_path = Path(item.filename.lower())
                        member_ext = member_path.suffix or (member_path.name if member_path.name in {".env", ".htaccess"} else "")
                        if member_ext not in SCAN_EXTENSIONS or member_ext == ".zip":
                            continue
                        supported_entries += 1
                        if item.file_size > MAX_ARCHIVE_MEMBER_BYTES or item.file_size + total_read > MAX_ARCHIVE_TOTAL_BYTES:
                            skipped_entries += 1
                            continue
                        if item.compress_size == 0 and item.file_size or (item.compress_size and item.file_size / item.compress_size > 200):
                            skipped_entries += 1
                            continue
                        try:
                            with archive.open(item) as member:
                                member_data = member.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                            if len(member_data) > MAX_ARCHIVE_MEMBER_BYTES:
                                skipped_entries += 1
                                continue
                            total_read += len(member_data)
                            child_name = f"{name} → {item.filename[:180]}"
                            documents.extend(_resource_documents(member_data, member_ext, child_name, url, archive_depth + 1))
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            skipped_entries += 1
                            continue
                    metadata["supportedEntries"] = str(supported_entries)
                    metadata["skippedEntries"] = str(skipped_entries)
                return documents
        except (zipfile.BadZipFile, OSError, RuntimeError):
            metadata["parseStatus"] = "ZIP no legible"
            findings = _archive_name_findings([])
            return [{"url": url, "name": name, "format": "Archivo ZIP", "method": "Contenedor ZIP no legible; no se extrajo.",
                     "metadata": metadata, "findings": findings,
                     "fileInfo": {"sizeBytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "type": "Archivo ZIP"}}]

    findings = _sensitive_findings(pairs)
    return [{
        "url": url, "name": name, "format": SCAN_EXTENSIONS.get(extension, "Archivo"), "method": method,
        "metadata": metadata, "findings": findings,
        "fileInfo": {"sizeBytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "type": SCAN_EXTENSIONS.get(extension, "Archivo")},
    }]


def _tiff_values(data, offset, endianness):
    """Lee valores TIFF acotados sin depender de librerías externas."""
    if offset < 0 or offset + 2 > len(data):
        return {}
    count = struct.unpack_from(endianness + "H", data, offset)[0]
    if count > 512 or offset + 2 + count * 12 > len(data):
        return {}
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 8: 2, 9: 4, 10: 8}
    entries = {}
    for index in range(count):
        entry_offset = offset + 2 + index * 12
        tag, kind, amount, inline = struct.unpack_from(endianness + "HHI4s", data, entry_offset)
        unit_size = sizes.get(kind)
        if not unit_size or amount > 4096:
            continue
        length = unit_size * amount
        if length <= 4:
            raw = inline[:length]
        else:
            value_offset = struct.unpack(endianness + "I", inline)[0]
            if value_offset + length > len(data):
                continue
            raw = data[value_offset:value_offset + length]
        if kind == 2:
            value = raw.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()
        elif kind in (5, 10):
            pair_format = endianness + ("II" if kind == 5 else "ii")
            value = [struct.unpack_from(pair_format, raw, pos) for pos in range(0, len(raw), 8)]
        elif kind in (1, 7):
            value = list(raw)
        else:
            number_format = {3: "H", 4: "I", 8: "h", 9: "i"}.get(kind)
            if not number_format:
                continue
            value = list(struct.unpack(endianness + number_format * amount, raw))
        entries[tag] = value
    return entries


def _tiff_text(value):
    if isinstance(value, str):
        return value[:500]
    if isinstance(value, list) and value and all(isinstance(item, int) for item in value):
        try:
            return bytes(value).split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()[:500]
        except ValueError:
            return ""
    return ""


def _tiff_coordinate(entries, value_tag, reference_tag):
    values = entries.get(value_tag)
    reference = _tiff_text(entries.get(reference_tag, "")).upper()
    if not isinstance(values, list) or len(values) < 3:
        return ""
    try:
        degrees = [numerator / denominator for numerator, denominator in values[:3] if denominator]
        if len(degrees) != 3:
            return ""
        decimal = degrees[0] + degrees[1] / 60 + degrees[2] / 3600
        if reference in ("S", "W"):
            decimal = -decimal
        return f"{decimal:.6f}"
    except (TypeError, ValueError, ZeroDivisionError):
        return ""


def _tiff_metadata(data):
    if len(data) < 8 or data[:2] not in (b"II", b"MM"):
        return {}
    endianness = "<" if data[:2] == b"II" else ">"
    if struct.unpack_from(endianness + "H", data, 2)[0] != 42:
        return {}
    first_ifd = struct.unpack_from(endianness + "I", data, 4)[0]
    primary = _tiff_values(data, first_ifd, endianness)
    metadata = {}
    text_tags = {
        0x010F: "cameraMake", 0x0110: "cameraModel", 0x0131: "imageSoftware",
        0x0132: "imageDate", 0x013B: "artist", 0x8298: "copyright",
    }
    for tag, key in text_tags.items():
        value = _tiff_text(primary.get(tag))
        if value:
            metadata[key] = value

    exif_pointer = primary.get(0x8769)
    if isinstance(exif_pointer, list) and exif_pointer:
        exif = _tiff_values(data, exif_pointer[0], endianness)
        for tag, key in ((0x9003, "dateTimeOriginal"), (0x9004, "dateTimeDigitized"),
                         (0xA430, "cameraOwner"), (0xA431, "cameraSerial"), (0xA434, "lensModel"),
                         (0xA420, "imageUniqueId")):
            value = _tiff_text(exif.get(tag))
            if value:
                metadata[key] = value
        for tag, key in ((0xA002, "imageWidth"), (0xA003, "imageHeight")):
            values = exif.get(tag)
            if isinstance(values, list) and values:
                metadata[key] = str(values[0])

    gps_pointer = primary.get(0x8825)
    if isinstance(gps_pointer, list) and gps_pointer:
        gps = _tiff_values(data, gps_pointer[0], endianness)
        latitude = _tiff_coordinate(gps, 0x0002, 0x0001)
        longitude = _tiff_coordinate(gps, 0x0004, 0x0003)
        if latitude:
            metadata["gpsLatitude"] = latitude
        if longitude:
            metadata["gpsLongitude"] = longitude
    return metadata


def _image_metadata(data, image_type):
    metadata = {}
    if image_type == "JPEG":
        position = 2
        segments = 0
        while position + 4 <= len(data) and data[position] == 0xFF and segments < 2000:
            while position < len(data) and data[position] == 0xFF:
                position += 1
            if position >= len(data):
                break
            marker = data[position]
            position += 1
            segments += 1
            if marker in (0xD9, 0xDA):
                break
            if marker in (0x01,) or 0xD0 <= marker <= 0xD7:
                continue
            if position + 2 > len(data):
                break
            length = struct.unpack_from(">H", data, position)[0]
            if length < 2 or position + length > len(data):
                break
            segment = data[position + 2:position + length]
            if marker == 0xE1 and segment.startswith(b"Exif\0\0"):
                metadata.update(_tiff_metadata(segment[6:]))
            elif marker == 0xE1 and b"<x:xmpmeta" in segment:
                begin = segment.find(b"<x:xmpmeta")
                finish = segment.find(b"</x:xmpmeta>", begin)
                if finish >= 0:
                    root = _safe_xml(segment[begin:finish + len(b"</x:xmpmeta>")])
                    metadata.update({key: value for key, value in _xml_values(root).items() if key not in metadata})
            position += length
    elif image_type == "TIFF":
        metadata.update(_tiff_metadata(data))
    elif image_type == "PNG":
        position = 8
        chunks = 0
        text_keys = {
            "title": "title", "author": "creator", "artist": "artist", "description": "description",
            "comment": "description", "keywords": "keywords", "software": "imageSoftware",
            "creation time": "date", "copyright": "copyright",
        }
        while position + 12 <= len(data) and chunks < 2000:
            length = struct.unpack_from(">I", data, position)[0]
            kind = data[position + 4:position + 8]
            start, end = position + 8, position + 8 + length
            if end + 4 > len(data):
                break
            value = data[start:end]
            chunks += 1
            if kind == b"eXIf":
                metadata.update(_tiff_metadata(value))
            elif kind == b"tEXt" and b"\0" in value:
                raw_key, raw_value = value.split(b"\0", 1)
                key = raw_key.decode("latin-1", errors="replace").strip().lower()
                mapped = text_keys.get(key)
                text = raw_value.decode("latin-1", errors="replace").strip()
                if mapped and text:
                    metadata.setdefault(mapped, text[:500])
            elif kind == b"iTXt" and b"\0" in value:
                parts = value.split(b"\0", 5)
                if len(parts) == 6 and parts[1] == b"\0" and parts[2] == b"\0":
                    key = parts[0].decode("latin-1", errors="replace").strip().lower()
                    mapped = text_keys.get(key)
                    text = parts[5].decode("utf-8", errors="replace").strip()
                    if mapped and text:
                        metadata.setdefault(mapped, text[:500])
            position = end + 4
    elif image_type == "WebP":
        position = 12
        chunks = 0
        while position + 8 <= len(data) and chunks < 1000:
            kind = data[position:position + 4]
            length = struct.unpack_from("<I", data, position + 4)[0]
            start, end = position + 8, position + 8 + length
            if end > len(data):
                break
            value = data[start:end]
            if kind == b"EXIF":
                if value.startswith(b"Exif\0\0"):
                    value = value[6:]
                metadata.update(_tiff_metadata(value))
            elif kind == b"XMP " and b"<x:xmpmeta" in value:
                begin = value.find(b"<x:xmpmeta")
                finish = value.find(b"</x:xmpmeta>", begin)
                if finish >= 0:
                    root = _safe_xml(value[begin:finish + len(b"</x:xmpmeta>")])
                    metadata.update({key: val for key, val in _xml_values(root).items() if key not in metadata})
            position = end + (length % 2)
            chunks += 1
    return metadata


class AudioTagCollector:
    """Decodifica algunos campos ID3 conocidos; nunca reproduce el audio."""

    FRAME_KEYS = {
        "TIT2": "title", "TPE1": "creator", "TPE2": "albumArtist", "TALB": "album",
        "TDRC": "date", "TYER": "date", "TENC": "application", "TSSE": "application",
        "TPUB": "company", "TCOP": "copyright", "TCOM": "composer",
    }

    @staticmethod
    def _decode_text(data):
        if not data:
            return ""
        encoding = data[0]
        raw = data[1:].rstrip(b"\0")
        codecs = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}
        return " ".join(raw.decode(codecs.get(encoding, "latin-1"), errors="replace").split())[:500]

    @classmethod
    def mp3(cls, data):
        metadata = {}
        if len(data) < 10 or data[:3] != b"ID3":
            return metadata
        version = data[3]
        if version not in (3, 4):
            return metadata
        size = sum((data[6 + index] & 0x7F) << (7 * (3 - index)) for index in range(4))
        position = 10
        end = min(len(data), position + size)
        frames = 0
        while position + 10 <= end and frames < 200:
            frame_id = data[position:position + 4].decode("ascii", errors="ignore")
            if not frame_id.strip("\0"):
                break
            frame_size = (sum((data[position + 4 + index] & 0x7F) << (7 * (3 - index)) for index in range(4))
                          if version == 4 else struct.unpack_from(">I", data, position + 4)[0])
            flags = data[position + 8:position + 10]
            frame_start, frame_end = position + 10, position + 10 + frame_size
            if frame_size <= 0 or frame_end > end:
                break
            if frame_id in cls.FRAME_KEYS and not (flags[0] & 0xC0 or flags[1] & 0xC0):
                text = cls._decode_text(data[frame_start:frame_end])
                if text:
                    metadata.setdefault(cls.FRAME_KEYS[frame_id], text)
            position = frame_end
            frames += 1
        return metadata


def _wav_metadata(data):
    metadata = {}
    position = 12
    tags = {
        b"INAM": "title", b"IART": "creator", b"IPRD": "album", b"ICRD": "date",
        b"ISFT": "application", b"IPUB": "company", b"ICOP": "copyright",
    }
    while position + 8 <= len(data):
        kind = data[position:position + 4]
        length = struct.unpack_from("<I", data, position + 4)[0]
        start, end = position + 8, position + 8 + length
        if end > len(data):
            break
        if kind == b"LIST" and length >= 4 and data[start:start + 4] == b"INFO":
            cursor = start + 4
            while cursor + 8 <= end:
                tag = data[cursor:cursor + 4]
                tag_length = struct.unpack_from("<I", data, cursor + 4)[0]
                value_start, value_end = cursor + 8, cursor + 8 + tag_length
                if value_end > end:
                    break
                key = tags.get(tag)
                text = data[value_start:value_end].split(b"\0", 1)[0].decode("latin-1", errors="replace").strip()
                if key and text:
                    metadata.setdefault(key, text[:500])
                cursor = value_end + (tag_length % 2)
        position = end + (length % 2)
    return metadata


def _zip_document_type(data):
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            names = set(archive.namelist())
            if "word/document.xml" in names:
                return ".docx", "Word (paquete Office)"
            if "xl/workbook.xml" in names:
                return ".xlsx", "Excel (paquete Office)"
            if "ppt/presentation.xml" in names:
                return ".pptx", "PowerPoint (paquete Office)"
            if "mimetype" in names:
                with archive.open("mimetype") as mime_file:
                    mime_type = mime_file.read(256).decode("ascii", errors="ignore")
                odf = {
                    "application/vnd.oasis.opendocument.text": (".odt", "OpenDocument Text"),
                    "application/vnd.oasis.opendocument.spreadsheet": (".ods", "OpenDocument Spreadsheet"),
                    "application/vnd.oasis.opendocument.presentation": (".odp", "OpenDocument Presentation"),
                }
                return odf.get(mime_type, ("", ""))
    except (zipfile.BadZipFile, OSError, RuntimeError):
        pass
    return "", ""


def _uploaded_file_analysis(data, original_name):
    """Identifica el formato y extrae propiedades conocidas sin guardar ni ejecutar el archivo."""
    name = str(original_name or "archivo").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(char for char in name if ord(char) >= 32 and ord(char) != 127)[:180] or "archivo"
    metadata = {}
    method = "Solo se identificaron formato, tamaño y SHA-256; no se interpretó ni ejecutó el contenido."
    if data.startswith(b"%PDF-"):
        file_type = "PDF"
        metadata, method = _pdf_metadata(data), "Metadatos PDF visibles en Info/XMP; no se descomprimen streams."
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        file_type = "Imagen PNG"
        metadata, method = _image_metadata(data, "PNG"), "Propiedades de texto y EXIF de PNG."
    elif data.startswith(b"\xff\xd8\xff"):
        file_type = "Imagen JPEG"
        metadata, method = _image_metadata(data, "JPEG"), "EXIF y XMP visibles en JPEG."
    elif data.startswith((b"II*\0", b"MM\0*")):
        file_type = "Imagen TIFF"
        metadata, method = _image_metadata(data, "TIFF"), "Etiquetas EXIF/TIFF reconocidas."
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        file_type = "Imagen WebP"
        metadata, method = _image_metadata(data, "WebP"), "EXIF/XMP visibles en WebP."
    elif data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        file_type = "Audio WAV"
        metadata, method = _wav_metadata(data), "Etiquetas INFO de WAV."
    elif data.startswith(b"ID3"):
        file_type = "Audio MP3"
        metadata, method = AudioTagCollector.mp3(data), "Etiquetas de texto ID3 conocidas; no se reproduce el audio."
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        file_type = "Imagen GIF"
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        extension, file_type = _zip_document_type(data)
        if extension:
            metadata, method = extract_document_metadata(data, extension)
        else:
            file_type = "Archivo ZIP"
            method = "Se identificó un contenedor ZIP; no se extrajeron sus archivos internos."
    elif data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        file_type = "Documento Office clásico (OLE)"
        method = "Contenedor Office clásico identificado; no se ejecutó y no se extrajeron sus propiedades internas."
    elif data.startswith(b"SQLite format 3\0"):
        file_type = "Base de datos SQLite"
    elif data.startswith(b"MZ"):
        file_type = "Ejecutable Windows (PE)"
    elif data.startswith(b"\x7fELF"):
        file_type = "Ejecutable ELF"
    elif data.startswith(b"{\\rtf"):
        file_type = "Documento RTF"
        method = "Formato RTF identificado; no se interpretó su contenido."
    elif len(data) > 1 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0:
        file_type = "Audio MP3"
        metadata, method = AudioTagCollector.mp3(data), "Etiquetas ID3 reconocidas si están presentes; no se reproduce el audio."
    else:
        try:
            sample = data[:4096].decode("utf-8")
            file_type = "Archivo de texto UTF-8" if "\0" not in sample else "Archivo binario sin formato reconocido"
        except UnicodeDecodeError:
            file_type = "Archivo binario sin formato reconocido"

    upload_extension = Path(name.lower()).suffix
    if not upload_extension and name.lower() in {".env", ".htaccess"}:
        upload_extension = name.lower()
    structured_extensions = {
        ".json", ".csv", ".xml", ".txt", ".ini", ".conf", ".env", ".bak", ".backup",
        ".sql", ".js", ".map", ".md", ".log", ".yaml", ".yml", ".toml", ".properties", ".htaccess",
    }
    analyzed_documents = None
    if file_type == "Archivo ZIP" and upload_extension == ".zip":
        analyzed_documents = _resource_documents(data, ".zip", name, "")
    elif file_type == "Archivo de texto UTF-8" and upload_extension in structured_extensions:
        analyzed_documents = _resource_documents(data, upload_extension, name, "")

    if analyzed_documents is not None:
        return {
            "source": "upload",
            "filename": name,
            "pagesScanned": 0,
            "filesFound": len(analyzed_documents),
            "documents": analyzed_documents,
            "warnings": [],
            "truncated": False,
            "limits": {"pages": SCAN_MAX_PAGES, "files": SCAN_MAX_FILES, "fileSizeMb": 5,
                       "uploadSizeMb": MAX_UPLOAD_BYTES // (1024 * 1024), "timeSeconds": SCAN_DEADLINE},
        }

    return {
        "source": "upload",
        "filename": name,
        "pagesScanned": 0,
        "filesFound": 1,
        "documents": [{
            "name": name,
            "format": file_type,
            "method": method,
            "metadata": metadata,
            "findings": _sensitive_findings(list(metadata.items())),
            "fileInfo": {
                "sizeBytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "type": file_type,
            },
        }],
        "warnings": [],
        "truncated": False,
        "limits": {"pages": SCAN_MAX_PAGES, "files": SCAN_MAX_FILES, "fileSizeMb": 5,
                   "uploadSizeMb": MAX_UPLOAD_BYTES // (1024 * 1024), "timeSeconds": SCAN_DEADLINE},
    }


def _parse_uploaded_part(content_type, body):
    if not content_type.lower().startswith("multipart/form-data"):
        raise ScanError("El archivo debe enviarse como formulario multipart.")
    headers = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii", errors="replace")
    message = BytesParser(policy=email.policy.default).parsebytes(headers + body)
    if not message.is_multipart():
        raise ScanError("No se pudo leer el archivo del formulario.")
    uploaded = []
    authorized = False
    for part in message.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        field_name = part.get_param("name", header="content-disposition")
        if field_name == "authorized" and (part.get_payload(decode=True) or b"").strip() == b"yes":
            authorized = True
            continue
        if field_name != "file":
            continue
        filename = part.get_filename()
        content = part.get_payload(decode=True) or b""
        if filename:
            uploaded.append((filename, content))
    if not authorized:
        raise ScanError("Confirma que tienes autorización para analizar este archivo.")
    if len(uploaded) != 1:
        raise ScanError("Selecciona un solo archivo para analizar.")
    filename, content = uploaded[0]
    if len(content) > MAX_UPLOAD_BYTES:
        raise UploadTooLarge("El archivo supera el máximo de 20 MB.")
    if not content:
        raise ScanError("El archivo está vacío.")
    return filename, content


def _same_site_base_url(start_url):
    parsed = urlsplit(start_url)
    path = parsed.path or "/"
    base_path = path if path.endswith("/") or not Path(path).suffix else path.rsplit("/", 1)[0] + "/"
    return urlunsplit((parsed.scheme, parsed.netloc, base_path, "", ""))


def _same_site_hint_urls(start_url):
    base_url = _same_site_base_url(start_url)
    return [urljoin(base_url, path) for path in SCAN_PATH_HINTS]


def _robots_targets(text, base_url, expected_host):
    targets = []
    for line in text.splitlines()[:2000]:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key, value = key.strip().lower(), value.strip()
        if key not in {"allow", "disallow", "sitemap"} or not value or value == "/":
            continue
        if "*" in value or "?" in value or len(targets) >= 50:
            continue
        candidate = urljoin(base_url, value)
        try:
            normalized, _ = _normalize_scan_url(candidate, expected_host, resolve=False)
            targets.append(normalized)
        except ScanError:
            continue
    return list(dict.fromkeys(targets))


def _sitemap_targets(data, expected_host):
    root = _safe_xml(data[:1_000_000])
    if root is None:
        return []
    targets = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1].lower() != "loc":
            continue
        value = (node.text or "").strip()
        if not value or len(targets) >= 50:
            continue
        try:
            normalized, _ = _normalize_scan_url(value, expected_host, resolve=False)
            targets.append(normalized)
        except ScanError:
            continue
    return list(dict.fromkeys(targets))


def _content_extension(path, content_type):
    lowered = path.lower()
    if Path(lowered).name == ".env":
        return ".env"
    if lowered.endswith("/.htaccess") or lowered == ".htaccess":
        return ".htaccess"
    if lowered.endswith("/.well-known/security.txt"):
        return ".txt"
    extension = Path(lowered).suffix
    if extension in SCAN_EXTENSIONS:
        return extension
    return {
        "application/json": ".json", "text/csv": ".csv", "application/xml": ".xml",
        "text/xml": ".xml", "text/plain": ".txt", "application/zip": ".zip",
        "application/javascript": ".js", "text/javascript": ".js",
        "image/jpeg": ".jpg", "image/png": ".png", "image/tiff": ".tiff",
        "image/webp": ".webp", "audio/mpeg": ".mp3", "audio/wav": ".wav",
    }.get(content_type, "")


def _script_targets(data, script_url, expected_host):
    """Encuentra source maps y rutas escritas como literales, sin ejecutar código."""
    text = data[:1_000_000].decode("utf-8", errors="replace")
    references = re.findall(r"(?m)^[ \t]*//[#@][ \t]*sourceMappingURL=([^\s*]+)", text)
    references.extend(re.findall(r"[\"']((?:/|\.{1,2}/)(?:api|admin|backup|config|private|intranet|dev|uploads|documents|old)/[^\"'\s<>]{1,240})[\"']", text, re.I))
    targets = []
    for reference in references[:100]:
        candidate = urljoin(script_url, reference)
        try:
            normalized, _ = _normalize_scan_url(candidate, expected_host, resolve=False)
            targets.append(normalized)
        except ScanError:
            continue
    return list(dict.fromkeys(targets))


def _metadata_scan(start_url):
    start, host = _normalize_scan_url(start_url)
    started = time.monotonic()
    queue = deque([start, *_same_site_hint_urls(start)])
    visited = set()
    visited_pages = set()
    seen_files = set()
    indexed_targets = set()
    documents = []
    warnings = []
    fetch_count = 0
    truncated = False
    base_url = _same_site_base_url(start)

    while queue and len(documents) < SCAN_MAX_FILES:
        if time.monotonic() - started > SCAN_DEADLINE or fetch_count >= SCAN_MAX_FETCHES:
            truncated = True
            break
        target = queue.popleft()
        if target in visited:
            continue
        visited.add(target)
        target_path = urlsplit(target).path.lower()
        target_extension = Path(target_path).suffix
        if target_path.endswith(("/.env", "/.htaccess")):
            target_extension = Path(target_path).name
        if len(visited_pages) >= SCAN_MAX_PAGES and target_extension not in SCAN_EXTENSIONS:
            truncated = True
            continue
        if fetch_count:
            time.sleep(0.2)
        fetch_count += 1
        try:
            final_url, content, content_type = _fetch_public_url(target, host)
        except ScanError as exc:
            if target == start:
                warnings.append(f"Página inicial omitida: {exc}")
            continue

        final = urlsplit(final_url)
        extension = _content_extension(final.path, content_type)
        is_html = "html" in content_type or final.path.lower().endswith((".html", ".htm", "/"))
        if is_html:
            if len(visited_pages) >= SCAN_MAX_PAGES:
                truncated = True
                continue
            visited_pages.add(final_url)
            parser = LinkCollector()
            try:
                parser.feed(content.decode("utf-8", errors="replace"))
            except Exception:
                warnings.append("Una página no se pudo interpretar como HTML.")
                continue
            page_text = " ".join(parser.text_parts)
            emails = list(dict.fromkeys(EMAIL_VALUE_RE.findall(page_text)))[:50]
            pairs = list(parser.metadata.items()) + parser.observed_pairs
            pairs.extend(("email", value) for value in emails)
            pairs.extend(_text_pairs(page_text))
            page_findings = _sensitive_findings(pairs)
            if (parser.metadata or page_findings) and len(documents) < SCAN_MAX_FILES:
                documents.append({
                    "url": urlunsplit((final.scheme, final.netloc, final.path, "", "")),
                    "name": Path(final.path).name or "Página principal",
                    "format": "Página HTML",
                    "method": "Metadatos del título y etiquetas meta; no se ejecutó JavaScript.",
                    "metadata": parser.metadata,
                    "findings": page_findings,
                    "fileInfo": {"sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest(), "type": "Página HTML"},
                })

            link_base = urljoin(final_url, parser.base_href) if parser.base_href else final_url
            for href in parser.links:
                candidate = urljoin(link_base, href)
                try:
                    candidate, _ = _normalize_scan_url(candidate, host, resolve=False)
                except ScanError:
                    continue
                candidate_path = urlsplit(candidate).path.lower()
                candidate_ext = Path(candidate_path).suffix
                if candidate_ext in {".css", ".ico", ".gif", ".svg", ".mp4", ".webm", ".woff", ".woff2", ".ttf"}:
                    continue
                if candidate not in visited and candidate not in queue and len(queue) + len(visited) < SCAN_MAX_FETCHES:
                    queue.append(candidate)
            for item in _script_targets(content, final_url, host):
                if item in indexed_targets:
                    continue
                if len(indexed_targets) >= SCAN_MAX_INDEXED_PATHS:
                    truncated = True
                    break
                indexed_targets.add(item)
                if item not in visited and item not in queue:
                    queue.append(item)
            continue

        if not extension:
            continue
        if final_url in seen_files:
            continue
        seen_files.add(final_url)
        if len(documents) >= SCAN_MAX_FILES:
            truncated = True
            break
        name = Path(final.path).name or "recurso"
        try:
            new_documents = _resource_documents(content, extension, name, urlunsplit((final.scheme, final.netloc, final.path, "", "")))
            if final.path.lower().endswith("/robots.txt"):
                extra = _robots_targets(content.decode("utf-8", errors="replace"), base_url, host)
                if extra:
                    new_documents[0]["metadata"]["discoveredRoutes"] = ", ".join(
                        urlsplit(item).path for item in extra[:50]
                    )
                    new_documents[0]["findings"].append({
                        "category": "Descubrimiento de rutas", "severity": "Medio", "count": len(extra),
                        "fields": ["Allow/Disallow/Sitemap"],
                        "explanation": "robots.txt enumera rutas para rastreadores, pero no controla quién puede leerlas.",
                        "mitigation": "Aplicar autenticación y permisos en el servidor; robots.txt no es un control de acceso.",
                    })
                    for item in extra:
                        if item in indexed_targets:
                            continue
                        if len(indexed_targets) >= SCAN_MAX_INDEXED_PATHS:
                            truncated = True
                            break
                        indexed_targets.add(item)
                        if item not in visited and item not in queue:
                            queue.append(item)
            elif final.path.lower().endswith("sitemap.xml"):
                extra = _sitemap_targets(content, host)
                new_documents[0]["metadata"]["urlCount"] = str(len(extra))
                for item in extra:
                    if item in indexed_targets:
                        continue
                    if len(indexed_targets) >= SCAN_MAX_INDEXED_PATHS:
                        truncated = True
                        break
                    indexed_targets.add(item)
                    if item not in visited and item not in queue:
                        queue.append(item)
            if extension in {".js", ".mjs"}:
                extra = _script_targets(content, final_url, host)
                for item in extra:
                    if item in indexed_targets:
                        continue
                    if len(indexed_targets) >= SCAN_MAX_INDEXED_PATHS:
                        truncated = True
                        break
                    indexed_targets.add(item)
                    if item not in visited and item not in queue:
                        queue.append(item)
            room = SCAN_MAX_FILES - len(documents)
            documents.extend(new_documents[:room])
            if len(new_documents) > room:
                truncated = True
                break
        except Exception as exc:
            warnings.append(f"Recurso {name} omitido: {type(exc).__name__}.")

    if queue and (len(visited_pages) >= SCAN_MAX_PAGES or len(documents) >= SCAN_MAX_FILES or fetch_count >= SCAN_MAX_FETCHES):
        truncated = True
    return {
        "host": host,
        "pagesScanned": len(visited_pages),
        "filesFound": len(seen_files),
        "documents": documents,
        "warnings": warnings[:20],
        "truncated": truncated,
        "limits": {
            "pages": SCAN_MAX_PAGES,
            "files": SCAN_MAX_FILES,
            "fileSizeMb": 5,
            "pathProbes": SCAN_MAX_PATH_PROBES,
            "indexedPaths": SCAN_MAX_INDEXED_PATHS,
            "timeSeconds": SCAN_DEADLINE,
        },
    }


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def lan_ip():
    """IP de la máquina en la red local (para que los estudiantes se conecten)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def mask_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.{parts[3]}"
    return ip[:8] + "…"


class Store:
    """Almacén de visitas en un archivo JSON, seguro entre hilos."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.visits = []
        if path.exists():
            try:
                self.visits = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.visits = []

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.visits, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def add(self, visit):
        with self.lock:
            self.visits.append(visit)
            self._save()

    def reset(self):
        with self.lock:
            self.visits = []
            self._save()

    def snapshot(self):
        with self.lock:
            return list(self.visits)


def device_key(visit):
    # Un "dispositivo" del aula = misma huella desde la misma IP. Así el modo
    # incógnito no cuenta como otro estudiante, pero dos PCs idénticos de una
    # sala de cómputo sí aparecen como dispositivos distintos con igual huella.
    return f"{visit['visitorId']}|{visit['ip']}"


def latest_per_device(visits):
    latest = {}
    for v in visits:
        latest[device_key(v)] = v
    return list(latest.values())


def attr_stats(devices, attrs):
    n = len(devices)
    stats = {}
    for key, value in attrs.items():
        same = sum(1 for d in devices if d["attrs"].get(key) == value)
        stats[key] = {
            "same": same,
            "total": n,
            "bits": round(math.log2(n / same), 2) if same else 0.0,
        }
    return stats


def shannon(values):
    counts = Counter(values)
    n = sum(counts.values())
    return -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0


def panel_payload(visits):
    devices = latest_per_device(visits)
    by_device = defaultdict(list)
    for v in visits:
        by_device[device_key(v)].append(v)
    fp_counts = Counter(d["visitorId"] for d in devices)

    rows = []
    for d in sorted(devices, key=lambda x: x["ts"], reverse=True):
        history = by_device[device_key(d)]
        rows.append({
            "visitorId": d["visitorId"],
            "ip": mask_ip(d["ip"]),
            "ua": d["attrs"].get("ua", ""),
            "screen": d["attrs"].get("screen", ""),
            "timezone": d["attrs"].get("timezone", ""),
            "visits": len(history),
            "cookies": len({h["cookieId"] for h in history}),
            "firstSeen": history[0]["ts"],
            "lastSeen": history[-1]["ts"],
            "shared": fp_counts[d["visitorId"]] - 1,
        })

    keys = sorted({k for d in devices for k in d["attrs"]})
    entropy = []
    for k in keys:
        vals = [d["attrs"].get(k, "∅") for d in devices]
        entropy.append({
            "key": k,
            "entropy": round(shannon(vals), 3),
            "distinct": len(set(vals)),
            "stable": k in STABLE_KEYS,
        })
    entropy.sort(key=lambda e: e["entropy"], reverse=True)

    unique = sum(1 for c in fp_counts.values() if c == 1)
    return {
        "devices": len(devices),
        "visits": len(visits),
        "fingerprints": len(fp_counts),
        "uniqueDevices": unique,
        "maxEntropy": round(math.log2(len(devices)), 3) if devices else 0,
        "rows": rows,
        "entropy": entropy,
        "recognizedWithoutCookie": sum(
            1 for d in by_device.values() if len({h["cookieId"] for h in d}) > 1
        ),
    }


class Handler(SimpleHTTPRequestHandler):
    store = None
    port = 8000

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def log_message(self, fmt, *args):
        if "/api/" in (self.path or "") and self.command == "POST":
            print(f"  · {self.client_address[0]}  {self.command} {self.path}")

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > 2_000_000:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return None

    def _read_multipart_file(self):
        content_type = self.headers.get("Content-Type", "")
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError as exc:
            raise ScanError("La solicitud del archivo no tiene una longitud válida.") from exc
        if length <= 0:
            raise ScanError("Selecciona un archivo para analizar.")
        if length > MAX_UPLOAD_BYTES + 1_000_000:
            self.close_connection = True
            raise UploadTooLarge("El archivo supera el máximo de 20 MB.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ScanError("La carga del archivo llegó incompleta.")
        return _parse_uploaded_part(content_type, body)

    def _is_local(self):
        return self.client_address[0] in ("127.0.0.1", "::1")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/panel":
            self.path = "/panel.html"
        elif path == "/api/info":
            return self._json({
                "url": f"http://{lan_ip()}:{self.port}/",
                "stableKeys": STABLE_KEYS,
                "isLocal": self._is_local(),
            })
        elif path == "/api/panel":
            return self._json(panel_payload(self.store.snapshot()))
        return super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/fingerprint":
            return self._fingerprint()
        if path == "/api/metadata-scan":
            body = self._read_json()
            if not isinstance(body, dict) or not isinstance(body.get("url"), str):
                return self._json({"error": "Indica la dirección web que quieres revisar."}, 400)
            if body.get("authorized") is not True:
                return self._json({"error": "Confirma que tienes autorización para auditar este sitio."}, 400)
            try:
                return self._json(_metadata_scan(body["url"]))
            except ScanError as exc:
                return self._json({"error": str(exc)}, 400)
            except Exception as exc:
                print(f"  ✖ Error interno en auditoría de metadatos: {type(exc).__name__}")
                return self._json({"error": "Ocurrió un error interno al analizar los documentos."}, 500)
        if path == "/api/metadata-upload":
            try:
                filename, content = self._read_multipart_file()
                return self._json(_uploaded_file_analysis(content, filename))
            except UploadTooLarge as exc:
                return self._json({"error": str(exc)}, 413)
            except ScanError as exc:
                return self._json({"error": str(exc)}, 400)
            except Exception as exc:
                print(f"  ✖ Error interno al analizar archivo: {type(exc).__name__}")
                return self._json({"error": "Ocurrió un error interno al analizar el archivo."}, 500)
        if path == "/api/reset":
            if not self._is_local():
                return self._json({"error": "Solo el equipo del docente puede reiniciar."}, 403)
            self.store.reset()
            return self._json({"ok": True})
        self._json({"error": "Ruta no encontrada"}, 404)

    def _server_attrs(self):
        """Lo que el servidor ve sin ejecutar JavaScript: fingerprinting pasivo."""
        h = self.headers
        return {
            "ip": self.client_address[0],
            "hAcceptLanguage": h.get("Accept-Language", "∅"),
            "hAcceptEncoding": h.get("Accept-Encoding", "∅"),
            "hAccept": h.get("Accept", "∅"),
            "hOrder": " › ".join(k.lower() for k in h.keys()),
        }

    def _fingerprint(self):
        body = self._read_json()
        if not isinstance(body, dict) or not isinstance(body.get("attrs"), dict):
            return self._json({"error": "Datos inválidos"}, 400)

        attrs = {
            str(k)[:64]: str(v)[:MAX_VALUE_LEN]
            for k, v in body["attrs"].items()
        }
        server_attrs = self._server_attrs()
        attrs.update(server_attrs)
        cookie_id = str(body.get("cookieId", ""))[:64] or "sin-cookie"

        stable = "\n".join(f"{k}={attrs.get(k, '∅')}" for k in STABLE_KEYS)
        visitor_id = sha256(stable)
        full_hash = sha256("\n".join(f"{k}={attrs[k]}" for k in sorted(attrs)))

        previous = self.store.snapshot()
        same_fp = [v for v in previous if v["visitorId"] == visitor_id]
        cookie_seen = any(v["cookieId"] == cookie_id for v in previous)

        visit = {
            "ts": time.time(),
            "ip": server_attrs["ip"],
            "cookieId": cookie_id,
            "visitorId": visitor_id,
            "fullHash": full_hash,
            "attrs": attrs,
        }
        self.store.add(visit)

        devices = latest_per_device(self.store.snapshot())
        twins = sum(
            1 for d in devices
            if d["visitorId"] == visitor_id and device_key(d) != device_key(visit)
        )
        self._json({
            "visitorId": visitor_id,
            "fullHash": full_hash,
            "stableKeys": STABLE_KEYS,
            "serverAttrs": server_attrs,
            "stats": attr_stats(devices, attrs),
            "devices": len(devices),
            "twins": twins,
            "recognized": {
                "byFingerprint": len(same_fp),
                "byCookie": cookie_seen,
                "firstSeen": same_fp[0]["ts"] if same_fp else None,
                "cookiesUsed": len({v["cookieId"] for v in same_fp} | {cookie_id}),
            },
        })


def main():
    parser = argparse.ArgumentParser(description="FingerPrint Lab — laboratorio de fingerprinting")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    Handler.store = Store(DATA_FILE)
    Handler.port = args.port
    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError:
        raise SystemExit(f"\n  ✖ El puerto {args.port} está ocupado. Prueba: python3 app.py --port 8765\n")

    ip = lan_ip()
    print("\n  🔎  FingerPrint Lab en marcha\n")
    print(f"     Estudiantes →  http://{ip}:{args.port}/")
    print(f"     Panel docente → http://localhost:{args.port}/panel")
    print("\n     Ctrl+C para detener\n")

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(f"http://localhost:{args.port}/panel")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Servidor detenido.")
        server.server_close()


if __name__ == "__main__":
    main()
