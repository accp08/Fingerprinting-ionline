// Recolectores: cada uno implementa una técnica real de fingerprinting.
// Devuelven { value, display?, image? }. `value` es lo que se compara entre
// visitantes; `display` es la versión legible para la clase.

const FONT_LIST = [
  "Arial", "Arial Black", "Arial Narrow", "Calibri", "Cambria", "Candara", "Comic Sans MS",
  "Consolas", "Constantia", "Corbel", "Courier New", "Franklin Gothic Medium", "Gabriola",
  "Georgia", "Impact", "Lucida Console", "Lucida Sans Unicode", "Palatino Linotype",
  "Segoe UI", "Segoe Print", "Segoe Script", "Tahoma", "Times New Roman", "Trebuchet MS",
  "Verdana", "Wingdings", "MS Gothic", "Bahnschrift", "Ink Free",
  "American Typewriter", "Avenir", "Avenir Next", "Baskerville", "Chalkboard", "Copperplate",
  "Didot", "Futura", "Geneva", "Gill Sans", "Helvetica", "Helvetica Neue", "Hoefler Text",
  "Menlo", "Monaco", "Optima", "Papyrus", "SF Pro", "Skia", "Zapfino", "Marker Felt",
  "Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans", "Cantarell", "Roboto", "Open Sans",
  "Source Sans Pro", "Fira Code", "JetBrains Mono", "Lato", "Montserrat",
  "Adobe Garamond Pro", "Myriad Pro", "Minion Pro", "Century Gothic", "Garamond",
  "Bookman Old Style", "Rockwell", "Agency FB", "Bauhaus 93", "Broadway",
];

function withTimeout(promise, ms, fallback) {
  return Promise.race([promise, new Promise(r => setTimeout(() => r(fallback), ms))]);
}

function canvasFingerprint() {
  const c = document.createElement("canvas");
  c.width = 300; c.height = 80;
  const x = c.getContext("2d");
  if (!x) return { value: "sin canvas" };
  const g = x.createLinearGradient(0, 0, 300, 0);
  g.addColorStop(0, "#ff3d71"); g.addColorStop(0.5, "#ffaa00"); g.addColorStop(1, "#00d68f");
  x.fillStyle = g; x.fillRect(0, 0, 300, 80);
  x.textBaseline = "alphabetic";
  x.fillStyle = "#1a1f36"; x.font = "bold 22px Arial";
  x.fillText("Huella ¿Ñ? 😃🔐 2026", 8, 30);
  x.fillStyle = "rgba(255,255,255,0.75)"; x.font = "18px 'Times New Roman'";
  x.fillText("Cwm fjordbank glyphs vext quiz", 10, 60);
  x.globalCompositeOperation = "multiply";
  x.fillStyle = "rgb(0,180,255)"; x.beginPath(); x.arc(250, 40, 26, 0, Math.PI * 2); x.fill();
  x.fillStyle = "rgb(255,0,200)"; x.beginPath(); x.arc(275, 40, 26, 0, Math.PI * 2); x.fill();
  const data = c.toDataURL();
  const h = cyrb53(data);
  return { value: h, display: `hash ${h}`, image: data };
}

function webglInfo() {
  const c = document.createElement("canvas");
  const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
  if (!gl) return { vendor: { value: "WebGL no disponible" }, params: { value: "WebGL no disponible" } };
  const dbg = gl.getExtension("WEBGL_debug_renderer_info");
  const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
  const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
  const exts = gl.getSupportedExtensions() || [];
  const params = [
    gl.getParameter(gl.MAX_TEXTURE_SIZE),
    Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []).join("x"),
    gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
    gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
    gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
    gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
    exts.sort().join(","),
  ].join("|");
  return {
    vendor: { value: `${vendor} — ${renderer}`, display: `${renderer}` },
    params: { value: cyrb53(params), display: `${exts.length} extensiones · textura máx ${gl.getParameter(gl.MAX_TEXTURE_SIZE)}px` },
  };
}

async function audioFingerprint() {
  const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!Ctx) return { value: "sin Web Audio" };
  const ctx = new Ctx(1, 5000, 44100);
  const osc = ctx.createOscillator();
  osc.type = "triangle";
  osc.frequency.value = 10000;
  const comp = ctx.createDynamicsCompressor();
  comp.threshold.value = -50; comp.knee.value = 40; comp.ratio.value = 12;
  comp.attack.value = 0; comp.release.value = 0.25;
  osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
  const buffer = await new Promise((resolve, reject) => {
    ctx.oncomplete = e => resolve(e.renderedBuffer);
    const p = ctx.startRendering();
    if (p && p.then) p.then(resolve, reject);
  });
  const data = buffer.getChannelData(0);
  let sum = 0;
  for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
  return { value: sum.toString(), display: sum.toFixed(10) };
}

function detectFonts() {
  const bases = ["monospace", "sans-serif", "serif"];
  const text = "mmmmmmmmmmlliWW@#ñ";
  const span = document.createElement("span");
  span.style.cssText = "position:absolute;left:-9999px;top:-9999px;font-size:72px;white-space:nowrap";
  span.textContent = text;
  document.body.appendChild(span);
  const baseSize = {};
  for (const b of bases) {
    span.style.fontFamily = b;
    baseSize[b] = `${span.offsetWidth}x${span.offsetHeight}`;
  }
  const found = FONT_LIST.filter(font => bases.some(b => {
    span.style.fontFamily = `'${font}', ${b}`;
    return `${span.offsetWidth}x${span.offsetHeight}` !== baseSize[b];
  }));
  span.remove();
  return {
    value: found.join(", ") || "ninguna",
    display: `${found.length} de ${FONT_LIST.length} probadas: ${found.slice(0, 6).join(", ")}${found.length > 6 ? "…" : ""}`,
  };
}

async function speechVoices() {
  if (!("speechSynthesis" in window)) return { value: "no soportado" };
  let voices = speechSynthesis.getVoices();
  if (!voices.length) {
    voices = await withTimeout(new Promise(r => {
      speechSynthesis.addEventListener("voiceschanged", () => r(speechSynthesis.getVoices()), { once: true });
    }), 1200, []);
  }
  const names = voices.map(v => `${v.name}(${v.lang})`).sort();
  return { value: names.length ? cyrb53(names.join("|")) : "0 voces", display: `${names.length} voces del sistema` };
}

function mq(q) { return window.matchMedia && matchMedia(q).matches; }

window.COLLECTORS = [
  { key: "ua", msg: "Leyendo el User-Agent…", run: () => ({ value: navigator.userAgent }) },
  { key: "platform", msg: "Consultando la plataforma…", run: () => ({ value: navigator.platform || "∅" }) },
  { key: "vendor", msg: "Identificando fabricante del navegador…", run: () => ({ value: navigator.vendor || "(vacío)" }) },
  { key: "webdriver", msg: "¿Eres un robot? Revisando navigator.webdriver…", run: () => ({ value: String(!!navigator.webdriver) }) },
  {
    key: "plugins", msg: "Enumerando plugins…", run: () => {
      const list = Array.from(navigator.plugins || []).map(p => p.name);
      return { value: `${list.join(",")}|pdf:${navigator.pdfViewerEnabled}`, display: `${list.length} plugins · visor PDF: ${navigator.pdfViewerEnabled ? "sí" : "no"}` };
    },
  },
  { key: "languages", msg: "Leyendo idiomas preferidos…", run: () => ({ value: (navigator.languages || [navigator.language]).join(", ") }) },
  {
    key: "timezone", msg: "Detectando zona horaria…", run: () => {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const off = -new Date().getTimezoneOffset() / 60;
      return { value: `${tz} (UTC${off >= 0 ? "+" : ""}${off})` };
    },
  },
  {
    key: "intl", msg: "Analizando formatos regionales…", run: () => {
      const o = Intl.DateTimeFormat().resolvedOptions();
      const sample = new Intl.NumberFormat().format(1234567.891) + " · " + new Date(Date.UTC(2026, 0, 31, 15)).toLocaleString();
      return { value: `${o.locale}|${o.calendar}|${o.numberingSystem}|${sample}`, display: `${o.locale} · ${sample}` };
    },
  },
  {
    key: "screen", msg: "Midiendo la pantalla…", run: () => {
      const s = window.screen;
      return { value: `${s.width}x${s.height} (disponible ${s.availWidth}x${s.availHeight})` };
    },
  },
  { key: "colorDepth", msg: "Profundidad de color…", run: () => ({ value: `${screen.colorDepth} bits` }) },
  { key: "pixelRatio", msg: "Densidad de píxeles…", run: () => ({ value: String(Math.round(devicePixelRatio * 100) / 100) }) },
  { key: "viewport", msg: "Tamaño de la ventana…", run: () => ({ value: `${innerWidth}x${innerHeight}` }) },
  { key: "hardwareConcurrency", msg: "Contando núcleos de CPU…", run: () => ({ value: String(navigator.hardwareConcurrency ?? "oculto") }) },
  { key: "deviceMemory", msg: "Estimando memoria RAM…", run: () => ({ value: navigator.deviceMemory ? `${navigator.deviceMemory} GB` : "no expuesta" }) },
  {
    key: "touch", msg: "Probando soporte táctil…", run: () => ({
      value: `puntos:${navigator.maxTouchPoints || 0}|touchstart:${"ontouchstart" in window}`,
      display: navigator.maxTouchPoints ? `Sí, ${navigator.maxTouchPoints} puntos táctiles` : "Sin pantalla táctil",
    }),
  },
  { key: "canvas", msg: "Dibujando en un canvas invisible…", run: canvasFingerprint, slow: true },
  { key: "webgl", msg: "Interrogando a la tarjeta gráfica (WebGL)…", run: webglInfo, multi: { webglVendor: "vendor", webglParams: "params" }, slow: true },
  { key: "audio", msg: "Generando audio silencioso y procesándolo…", run: () => withTimeout(audioFingerprint(), 2500, { value: "tiempo agotado" }), slow: true },
  { key: "fonts", msg: `Probando ${FONT_LIST.length} fuentes tipográficas…`, run: detectFonts, slow: true },
  { key: "voices", msg: "Listando voces de síntesis…", run: speechVoices },
  {
    key: "math", msg: "Calculando funciones matemáticas…", run: () => {
      const v = [Math.tan(-1e300), Math.sinh(1), Math.expm1(1), Math.cbrt(100), Math.atanh(0.5), Math.pow(Math.PI, -100), Math.log1p(10)];
      return { value: v.join("|"), display: `tan(-1e300) = ${v[0]}` };
    },
  },
  { key: "cookies", msg: "¿Cookies habilitadas?", run: () => ({ value: navigator.cookieEnabled ? "habilitadas" : "deshabilitadas" }) },
  {
    key: "dnt", msg: "Señales de privacidad (DNT/GPC)…", run: () => ({
      value: `DNT:${navigator.doNotTrack ?? window.doNotTrack ?? "∅"}|GPC:${navigator.globalPrivacyControl ?? "∅"}`,
    }),
  },
  {
    key: "storage", msg: "Probando almacenamiento local…", run: () => {
      const test = name => { try { const s = window[name]; s.setItem("_fp", "1"); s.removeItem("_fp"); return "sí"; } catch (e) { return "no"; } };
      return { value: `localStorage:${test("localStorage")}|sessionStorage:${test("sessionStorage")}|indexedDB:${"indexedDB" in window ? "sí" : "no"}` };
    },
  },
  {
    key: "mediaQueries", msg: "Leyendo preferencias visuales y de accesibilidad…", run: () => {
      const p = [
        mq("(prefers-color-scheme: dark)") ? "oscuro" : "claro",
        mq("(prefers-reduced-motion: reduce)") ? "menos-movimiento" : "",
        mq("(prefers-contrast: more)") ? "alto-contraste" : "",
        mq("(forced-colors: active)") ? "colores-forzados" : "",
        mq("(pointer: coarse)") ? "puntero-dedo" : "puntero-fino",
        mq("(hover: hover)") ? "hover" : "sin-hover",
        mq("(color-gamut: p3)") ? "gama-P3" : "gama-sRGB",
      ].filter(Boolean);
      return { value: p.join(", ") };
    },
  },
  {
    key: "connection", msg: "Tipo de conexión de red…", run: () => {
      const c = navigator.connection;
      return { value: c ? `${c.effectiveType || "?"} · ${c.downlink ?? "?"} Mbps · RTT ${c.rtt ?? "?"} ms` : "no expuesta" };
    },
  },
];
