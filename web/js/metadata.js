// Auditoría didáctica de metadatos en documentos enlazados desde una web.
const metadataForm = document.querySelector("#metadataForm");
const metadataStatus = document.querySelector("#metadataStatus");
const metadataStart = document.querySelector("#metadataStart");
const metadataUploadForm = document.querySelector("#metadataUploadForm");
const metadataUploadStatus = document.querySelector("#metadataUploadStatus");
const metadataUploadStart = document.querySelector("#metadataUploadStart");
const metadataReportActions = document.querySelector("#metadataReportActions");
const metadataExport = document.querySelector("#metadataExport");
const metadataResults = document.querySelector("#metadataResults");
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
let currentMetadataReport = null;
let activeMetadataSeverity = "all";

const METADATA_GUIDE = {
  title: ["Título", "Contexto", "El título puede revelar el nombre de un proyecto o documento interno."],
  subject: ["Tema", "Contexto", "El tema puede describir el propósito del archivo o el asunto de un trabajo."],
  description: ["Descripción", "Contexto", "Una descripción puede contener detalles que no se ven en la página pública."],
  keywords: ["Palabras clave", "Contexto", "Las palabras clave pueden revelar nombres de proyectos o temas de interés."],
  creator: ["Autor", "Identidad", "Puede revelar el nombre o correo de quien creó el archivo y facilitar suplantación dirigida."],
  artist: ["Artista", "Identidad", "Puede identificar a la persona que produjo la imagen o grabación."],
  cameraOwner: ["Propietario de cámara", "Identidad", "Puede vincular la imagen con una persona concreta."],
  cameraSerial: ["Número de serie de cámara", "Identidad", "Puede identificar y correlacionar un dispositivo físico."],
  imageUniqueId: ["Identificador único de imagen", "Identidad", "Puede permitir reconocer la misma imagen entre publicaciones."],
  "initial-creator": ["Autor inicial", "Identidad", "Puede identificar a la primera persona que creó el documento."],
  lastmodifiedby: ["Última persona editora", "Identidad", "Puede revelar quién editó el archivo más recientemente."],
  manager: ["Responsable", "Organización", "Puede señalar roles o relaciones internas de la organización."],
  company: ["Organización", "Organización", "Puede confirmar el nombre de la empresa, institución o equipo."],
  template: ["Plantilla", "Entorno técnico", "El nombre de una plantilla puede revelar convenciones o nombres internos."],
  application: ["Aplicación", "Entorno técnico", "Identifica el programa que guardó o creó el archivo."],
  appversion: ["Versión de la aplicación", "Entorno técnico", "Una versión antigua puede orientar una búsqueda de fallos conocidos; por sí sola no demuestra que haya un fallo."],
  generator: ["Programa generador", "Entorno técnico", "Puede identificar la herramienta que creó o exportó el archivo."],
  creatortool: ["Programa generador", "Entorno técnico", "Puede identificar la herramienta que creó o exportó el archivo."],
  imageSoftware: ["Software de imagen", "Entorno técnico", "Puede identificar el programa o flujo de edición utilizado."],
  cameraMake: ["Marca de cámara", "Entorno técnico", "Puede revelar el fabricante del dispositivo de captura."],
  cameraModel: ["Modelo de cámara", "Entorno técnico", "Puede revelar el modelo del dispositivo de captura."],
  lensModel: ["Modelo de lente", "Entorno técnico", "Puede aportar detalles sobre el equipo usado para capturar la imagen."],
  imageWidth: ["Ancho de imagen", "Información", "Las dimensiones pueden ayudar a reconocer el dispositivo o flujo de trabajo."],
  imageHeight: ["Alto de imagen", "Información", "Las dimensiones pueden ayudar a reconocer el dispositivo o flujo de trabajo."],
  gpsLatitude: ["Latitud GPS", "Ubicación", "Puede revelar el lugar exacto donde se tomó la imagen."],
  gpsLongitude: ["Longitud GPS", "Ubicación", "Puede revelar el lugar exacto donde se tomó la imagen."],
  dateTimeOriginal: ["Fecha y hora de captura", "Actividad", "Puede revelar cuándo se tomó la imagen."],
  dateTimeDigitized: ["Fecha de digitalización", "Actividad", "Puede revelar cuándo se procesó la imagen."],
  imageDate: ["Fecha de imagen", "Actividad", "Puede revelar cuándo se capturó o modificó la imagen."],
  album: ["Álbum", "Contexto", "El nombre del álbum puede revelar el tema o contexto del audio."],
  albumArtist: ["Artista del álbum", "Identidad", "Puede identificar a quien produjo o publicó el audio."],
  composer: ["Compositor", "Identidad", "Puede identificar a la persona que compuso el audio."],
  copyright: ["Derechos de autor", "Organización", "Puede revelar titularidad o datos de publicación."],
  "creation-date": ["Fecha de creación", "Actividad", "Puede revelar cuándo se empezó a preparar el documento."],
  createdate: ["Fecha de creación", "Actividad", "Puede revelar cuándo se empezó a preparar el documento."],
  created: ["Fecha de creación", "Actividad", "Puede revelar cuándo se empezó a preparar el documento."],
  modified: ["Fecha de modificación", "Actividad", "Puede revelar actividad reciente o etapas de preparación."],
  modifydate: ["Fecha de modificación", "Actividad", "Puede revelar actividad reciente o etapas de preparación."],
  date: ["Fecha", "Actividad", "Puede revelar cuándo se editó o publicó el documento."],
  revision: ["Revisión", "Actividad", "El número de revisión puede dar pistas sobre el proceso de edición."],
  "editing-cycles": ["Ciclos de edición", "Actividad", "Puede dar una idea de cuánto se modificó el archivo."],
  "editing-duration": ["Tiempo de edición", "Actividad", "Puede revelar cuánto tiempo se trabajó en el archivo."],
  total_time: ["Tiempo total", "Actividad", "Puede dar una pista aproximada del tiempo dedicado al documento."],
  totaltime: ["Tiempo total", "Actividad", "Puede dar una pista aproximada del tiempo dedicado al documento."],
  recordCount: ["Registros", "Información", "Cantidad de filas o registros; puede dimensionar el alcance de una exposición."],
  lineCount: ["Líneas", "Información", "Tamaño aproximado del recurso de texto."],
  sizeBytes: ["Tamaño del recurso", "Información", "Ayuda a describir el archivo sin interpretar su contenido."],
  fields: ["Campos detectados", "Información", "El esquema puede revelar qué tipo de datos contiene un archivo."],
  sourceCount: ["Archivos fuente", "Entorno técnico", "Un mapa de fuentes puede revelar estructura y código original del cliente."],
  embeddedSources: ["Fuentes embebidas", "Entorno técnico", "El mapa conserva contenido fuente publicado junto al JavaScript."],
  entryCount: ["Entradas en el ZIP", "Información", "Los nombres internos pueden revelar respaldos, configuración o datos de trabajo."],
  supportedEntries: ["Miembros reconocidos", "Información", "Cantidad de elementos del ZIP con un formato que el laboratorio puede revisar."],
  skippedEntries: ["Miembros omitidos", "Información", "Se omitieron por límites de tamaño, compresión o cantidad; no se analizaron."],
  uncompressedBytes: ["Tamaño descomprimido", "Información", "Permite dimensionar el contenido del archivo sin ejecutarlo."],
  compressedBytes: ["Tamaño comprimido", "Información", "Tamaño del archivo recibido."],
  urlCount: ["Direcciones en sitemap", "Entorno técnico", "Un sitemap enumera rutas, pero no controla quién puede acceder a ellas."],
  discoveredRoutes: ["Rutas declaradas", "Entorno técnico", "robots.txt puede anunciar rutas; no es un mecanismo de autorización."],
  parseStatus: ["Estado del formato", "Información", "El recurso se identificó, pero su contenido estructurado no pudo interpretarse."],
  sha256: ["Huella SHA-256", "Información", "Permite comparar si dos copias de un archivo son iguales."],
  disallow: ["Ruta en robots.txt", "Entorno técnico", "La directiva no impide que una persona solicite esa ruta."],
  allow: ["Ruta en robots.txt", "Entorno técnico", "La directiva orienta rastreadores y no concede ni revoca permisos."],
};

function escapeMetadata(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);
}

function metadataRiskForField(key) {
  const guide = METADATA_GUIDE[key] || [key, "Información"];
  if (["Identidad", "Ubicación"].includes(guide[1])) return "high";
  if (["Organización", "Entorno técnico", "Contexto"].includes(guide[1])) return "medium";
  return "low";
}

function metadataDocumentRisk(doc) {
  const rank = { low: 0, medium: 1, high: 2 };
  const risks = Object.keys(doc.metadata || {}).map(metadataRiskForField);
  for (const finding of doc.findings || []) {
    risks.push(finding.severity === "Alto" ? "high" : finding.severity === "Medio" ? "medium" : "low");
  }
  return risks.reduce((highest, risk) => rank[risk] > rank[highest] ? risk : highest, "low");
}

function applyMetadataSeverityFilter() {
  const results = document.querySelector("#metadataResults");
  const documents = [...results.querySelectorAll(".metadata-document")];
  let visible = 0;
  for (const doc of documents) {
    const show = activeMetadataSeverity === "all" || doc.dataset.severity === activeMetadataSeverity;
    doc.hidden = !show;
    if (show) visible += 1;
  }
  for (const button of results.querySelectorAll("[data-metadata-filter]")) {
    const selected = button.dataset.metadataFilter === activeMetadataSeverity;
    button.setAttribute("aria-pressed", String(selected));
  }
  const count = results.querySelector("#metadataFilterCount");
  if (count) count.textContent = `Mostrando ${visible} de ${documents.length} recursos.`;
}

function renderMetadataReport(report) {
  const docs = Array.isArray(report.documents) ? report.documents : [];
  const uploaded = report.source === "upload";
  const records = docs.reduce((sum, doc) => sum + Object.keys(doc.metadata || {}).length, 0);
  const sensitiveMatches = docs.reduce((sum, doc) => sum + (doc.findings || []).reduce((subtotal, finding) => subtotal + (finding.count || 0), 0), 0);
  currentMetadataReport = report;
  metadataReportActions.hidden = false;

  document.querySelector("#metadataSummary").hidden = false;
  document.querySelector("#metadataSummary").innerHTML = `
    <div class="card metadata-summary-card">
      <div><span class="eyebrow">${uploaded ? "Archivo analizado" : "Sitio revisado"}</span><b class="metadata-domain">${escapeMetadata(uploaded ? report.filename : report.host)}</b></div>
      <div><b>${uploaded ? 1 : report.pagesScanned}</b><span>${uploaded ? "archivo recibido" : "páginas visitadas"}</span></div>
      <div><b>${docs.length}</b><span>${uploaded ? "archivo analizado" : "recursos analizados"}</span></div>
      <div><b>${records}</b><span>metadatos encontrados</span></div>
      <div><b class="${sensitiveMatches ? "risk-high" : ""}">${sensitiveMatches}</b><span>coincidencias sensibles clasificadas</span></div>
    </div>
    <p class="muted metadata-scope">${uploaded
      ? "El archivo se procesó en memoria en el servidor del laboratorio. Los formatos no reconocidos solo muestran datos básicos de identificación."
      : "Se revisaron enlaces, mapas públicos, recursos estáticos y rutas comunes del dominio. El resultado no enumera recursos protegidos ni todos los archivos que podrían existir."}</p>`;

  const warnings = [...(report.warnings || [])];
  if (report.truncated) warnings.push(`Se alcanzó un límite: hasta ${report.limits.pages} páginas, ${report.limits.files} archivos, ${report.limits.pathProbes} rutas comunes, ${report.limits.indexedPaths} rutas indexadas, 5 MB por archivo o ${Math.round(report.limits.timeSeconds / 60)} minutos de ejecución.`);
  const warningsBox = document.querySelector("#metadataWarnings");
  warningsBox.hidden = warnings.length === 0;
  warningsBox.innerHTML = warnings.length
    ? `<div class="banner info"><div class="big">ℹ️</div><div><h3>Alcance y avisos</h3><ul>${warnings.map(w => `<li>${escapeMetadata(w)}</li>`).join("")}</ul></div></div>`
    : "";

  const results = document.querySelector("#metadataResults");
  activeMetadataSeverity = "all";
  if (!docs.length) {
    results.innerHTML = `<div class="card metadata-empty"><b>No se encontraron metadatos legibles.</b><p>Puede que el sitio no enlace documentos compatibles, que los datos se hayan eliminado o que el servidor no permita leer esos archivos.</p></div>`;
    return;
  }

  const docsBySeverity = { high: 0, medium: 0, low: 0 };
  const documentCards = docs.map((doc, index) => {
    const entries = Object.entries(doc.metadata || {});
    const severity = metadataDocumentRisk(doc);
    const severityLabels = { high: "Alta", medium: "Media", low: "Baja" };
    docsBySeverity[severity] += 1;
    const fields = entries.length ? entries.map(([key, value]) => {
      const guide = METADATA_GUIDE[key] || [key, "Información", "Este dato puede aportar contexto sobre el archivo o su entorno."];
      const riskClass = `risk-${metadataRiskForField(key)}`;
      const riskLabel = riskClass === "risk-high" ? "Riesgo alto" : riskClass === "risk-medium" ? "Riesgo medio" : "Riesgo bajo";
      const valueMarkup = `<code class="metadata-value">${escapeMetadata(value)}</code>`;
      return `<div class="metadata-field">
        <div class="metadata-field-heading"><b>${escapeMetadata(guide[0])}</b><span class="pill ${riskClass}">${riskLabel} · ${escapeMetadata(guide[1])}</span></div>
        ${valueMarkup}
        <p>${escapeMetadata(guide[2])}</p>
      </div>`;
    }).join("") : `<p class="muted">No se detectaron propiedades conocidas en este archivo.</p>`;
    const findings = (doc.findings || []).map(finding => {
      const riskClass = finding.severity === "Alto" ? "risk-high" : "risk-medium";
      const fieldsList = (finding.fields || []).map(escapeMetadata).join(", ") || "Sin campos identificados";
      return `<div class="metadata-finding ${riskClass}">
        <div class="metadata-field-heading"><b>${escapeMetadata(finding.category)}</b><span class="pill ${riskClass}">Riesgo ${escapeMetadata(finding.severity)}</span></div>
        <p><b>${new Intl.NumberFormat("es-CO").format(finding.count || 0)} coincidencias clasificadas</b>; campos: <code>${fieldsList}</code>. La detección agrupa los datos por categoría y campo.</p>
        <p>${escapeMetadata(finding.explanation)}</p>
        <p><b>Mitigación:</b> ${escapeMetadata(finding.mitigation)}</p>
      </div>`;
    }).join("");
    const fileInfo = doc.fileInfo ? `<div class="metadata-file-info">
      <div><b>Tipo detectado</b><span>${escapeMetadata(doc.fileInfo.type)}</span></div>
      <div><b>Tamaño</b><span>${new Intl.NumberFormat("es-CO").format(doc.fileInfo.sizeBytes)} bytes</span></div>
      <div><b>Huella SHA-256</b><code>${escapeMetadata(doc.fileInfo.sha256)}</code></div>
    </div>` : "";
    return `<article class="card metadata-document" data-severity="${severity}">
      <div class="metadata-document-head"><span class="metadata-file-icon">📄</span><div><span class="pill">${escapeMetadata(doc.format)}</span><h3>${escapeMetadata(doc.name)}</h3>${doc.url ? `<code>${escapeMetadata(doc.url)}</code>` : ""}</div><span class="pill risk-${severity}">Criticidad ${severityLabels[severity]}</span><span class="metadata-number">${index + 1}</span></div>
      <p class="muted metadata-method">${escapeMetadata(doc.method)}</p>
      ${fileInfo}
      <div class="metadata-fields">${fields}</div>
      ${findings ? `<div class="metadata-findings"><h4>Señales de confidencialidad</h4>${findings}</div>` : ""}
    </article>`;
  }).join("");
  const filters = [
    ["all", "Todas", docs.length],
    ["high", "Alta", docsBySeverity.high],
    ["medium", "Media", docsBySeverity.medium],
    ["low", "Baja", docsBySeverity.low],
  ];
  results.innerHTML = `<div class="metadata-filter-bar" role="group" aria-label="Filtrar resultados por criticidad">
    <span>Filtrar por criticidad</span>
    ${filters.map(([value, label, count]) => `<button class="metadata-filter" type="button" data-metadata-filter="${value}" aria-pressed="${value === "all"}" ${count === 0 ? "disabled" : ""}>${label} <span>${count}</span></button>`).join("")}
  </div><p id="metadataFilterCount" class="muted metadata-filter-count" aria-live="polite"></p><div class="metadata-result-list">${documentCards}</div>`;
  applyMetadataSeverityFilter();
}

metadataResults.addEventListener("click", event => {
  const button = event.target.closest("[data-metadata-filter]");
  if (!button || button.disabled) return;
  activeMetadataSeverity = button.dataset.metadataFilter;
  applyMetadataSeverityFilter();
});

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function downloadMetadataReport() {
  if (!currentMetadataReport) return;
  const rows = [["Archivo", "URL", "Categoría", "Riesgo", "Coincidencias", "Campos", "Explicación", "Mitigación"]];
  for (const doc of currentMetadataReport.documents || []) {
    for (const finding of doc.findings || []) {
      rows.push([doc.name, doc.url || "", finding.category, finding.severity, finding.count || 0,
        (finding.fields || []).join("; "), finding.explanation, finding.mitigation]);
    }
  }
  if (rows.length === 1) rows.push(["Sin hallazgos clasificados", "", "", "", 0, "", "No se detectaron coincidencias en las categorías configuradas.", "Revisar manualmente los recursos y el alcance del análisis."]);
  const csv = "\uFEFF" + rows.map(row => row.map(csvCell).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "informe-confidencialidad-redactado.csv";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

metadataExport.addEventListener("click", downloadMetadataReport);

metadataForm.addEventListener("submit", async event => {
  event.preventDefault();
  const url = document.querySelector("#metadataUrl").value.trim();
  const authorized = document.querySelector("#metadataAuthorized").checked;
  if (!authorized) return;

  metadataStart.disabled = true;
  metadataStart.textContent = "⏳ Revisando…";
  metadataForm.setAttribute("aria-busy", "true");
  metadataStatus.innerHTML = `<span class="metadata-loading" role="status"><span class="metadata-spinner" aria-hidden="true"></span><span>Revisando páginas, mapas, rutas comunes y archivos públicos del dominio…</span></span>`;
  document.querySelector("#metadataSummary").hidden = true;
  metadataReportActions.hidden = true;
  document.querySelector("#metadataWarnings").hidden = true;
  document.querySelector("#metadataResults").innerHTML = "";

  try {
    const response = await fetch("/api/metadata-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, authorized }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "No se pudo completar el escaneo.");
    renderMetadataReport(data);
    metadataStatus.textContent = `Análisis terminado: ${data.pagesScanned} páginas y ${data.filesFound} recursos revisados. Los metadatos encontrados se muestran con sus valores y criticidad; los resultados no se guardan.`;
  } catch (error) {
    metadataStatus.textContent = error instanceof TypeError
      ? "No se pudo conectar con la API del laboratorio. Comprueba que el servidor esté en marcha y vuelve a intentarlo."
      : error.message || "No se pudo completar la revisión.";
  } finally {
    metadataForm.setAttribute("aria-busy", "false");
    metadataStart.disabled = false;
    metadataStart.textContent = "▶ Revisar documentos";
  }
});

metadataUploadForm.addEventListener("submit", async event => {
  event.preventDefault();
  const file = document.querySelector("#metadataFile").files[0];
  if (!file) return;
  if (file.size > MAX_UPLOAD_BYTES) {
    metadataUploadStatus.textContent = "El archivo supera el máximo permitido de 20 MB.";
    return;
  }

  metadataUploadStart.disabled = true;
  metadataUploadStart.textContent = "⏳ Analizando…";
  metadataUploadStatus.textContent = "Enviando el archivo al servidor del laboratorio para analizarlo en memoria…";
  document.querySelector("#metadataSummary").hidden = true;
  metadataReportActions.hidden = true;
  document.querySelector("#metadataWarnings").hidden = true;
  document.querySelector("#metadataResults").innerHTML = "";

  try {
    const response = await fetch("/api/metadata-upload", {
      method: "POST",
      body: new FormData(metadataUploadForm),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "No se pudo analizar el archivo.");
    renderMetadataReport(data);
    metadataUploadStatus.textContent = "Análisis terminado. El archivo no se guardó ni se ejecutó.";
  } catch (error) {
    metadataUploadStatus.textContent = error instanceof TypeError
      ? "No se pudo conectar con el servidor del laboratorio. Comprueba que siga en marcha."
      : error.message || "No se pudo completar el análisis.";
  } finally {
    metadataUploadStart.disabled = false;
    metadataUploadStart.textContent = "📄 Analizar archivo";
  }
});
