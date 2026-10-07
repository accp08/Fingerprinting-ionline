// Lógica de la página del estudiante: pestañas, escaneo animado, resultados y teoría.

const $ = sel => document.querySelector(sel);
const STEP_DELAY = 110; // ms entre pruebas: suficiente para que la clase lo siga en el proyector
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ---------------- Pestañas ---------------- */
function showView(name) {
  document.querySelectorAll(".view").forEach(v => v.classList.toggle("active", v.id === `view-${name}`));
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === name));
  window.scrollTo({ top: 0, behavior: "smooth" });
}
document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", () => showView(t.dataset.view)));
document.querySelectorAll("[data-goto]").forEach(b => b.addEventListener("click", () => showView(b.dataset.goto)));

/* ---------------- Ilustración de huella dactilar ---------------- */
(function drawFingerprintArt() {
  const svg = $("#fpArt");
  let paths = "";
  for (let i = 0; i < 11; i++) {
    const rx = 12 + i * 6.5, ry = 16 + i * 7.5;
    const gap = (i * 37) % 70 + 20;
    const len = Math.PI * (rx + ry);
    paths += `<ellipse class="ridge" cx="100" cy="100" rx="${rx}" ry="${ry}"
      stroke-dasharray="${len * 0.62} ${gap}" stroke-dashoffset="${i * 23}"
      transform="rotate(${(i % 3) * 6 - 6} 100 100)" opacity="${1 - i * 0.05}"/>`;
  }
  svg.insertAdjacentHTML("beforeend", paths);
})();

/* ---------------- Identidad por cookie (para comparar con la huella) ---------------- */
function getCookieId() {
  let id = null;
  try { id = localStorage.getItem("fp-demo-id"); } catch (e) { /* bloqueado */ }
  if (!id) {
    const m = document.cookie.match(/(?:^|; )fp_demo_id=([^;]+)/);
    id = m ? m[1] : null;
  }
  const isNew = !id;
  if (!id) id = "c-" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
  try { localStorage.setItem("fp-demo-id", id); } catch (e) { /* bloqueado */ }
  document.cookie = `fp_demo_id=${id}; max-age=31536000; path=/; SameSite=Lax`;
  return { id, isNew };
}

/* ---------------- Escaneo ---------------- */
let lastResult = null;
let activeFilter = "all";

function log(html, cls = "") {
  const t = $("#terminal");
  t.insertAdjacentHTML("beforeend", `<div class="line ${cls}">${html}</div>`);
  t.scrollTop = t.scrollHeight;
}

function short(v, n = 70) {
  v = String(v);
  return v.length > n ? v.slice(0, n) + "…" : v;
}

async function runScan() {
  $("#intro").hidden = true;
  $("#results").hidden = true;
  $("#scanning").hidden = false;
  $("#terminal").innerHTML = "";
  window.scrollTo({ top: 0, behavior: "smooth" });

  const attrs = {}, extra = {};
  const total = COLLECTORS.length;
  log("$ fingerprint --scan --verbose", "head");
  log("Iniciando recolección. Nada de esto requiere permisos ni muestra avisos.\n", "run");

  for (let i = 0; i < total; i++) {
    const c = COLLECTORS[i];
    log(`▶ ${escapeHtml(c.msg)}`, "run");
    let result;
    try {
      result = await c.run();
    } catch (e) {
      result = { value: `error: ${e.message}` };
    }
    const entries = c.multi
      ? Object.entries(c.multi).map(([key, sub]) => [key, result[sub]])
      : [[c.key, result]];
    for (const [key, r] of entries) {
      attrs[key] = String(r.value);
      extra[key] = r;
      const label = CATALOG[key]?.label || key;
      log(`  ✔ ${escapeHtml(label)}: <span class="val">${escapeHtml(short(r.display ?? r.value))}</span>`, "ok");
    }
    const partial = cyrb53(Object.values(attrs).join("|"));
    $("#liveIdenticon").innerHTML = identicon(partial, 180);
    $("#liveHash").textContent = partial;
    $("#progressBar").style.width = `${((i + 1) / total) * 100}%`;
    $("#progressText").textContent = `${i + 1} / ${total} técnicas`;
    await sleep(c.slow ? STEP_DELAY * 3 : STEP_DELAY);
  }

  log("\n▶ Enviando al servidor (aquí el servidor añade lo que ve de forma pasiva: IP y cabeceras HTTP)…", "run");
  const cookie = getCookieId();
  let server = null;
  try {
    const res = await fetch("/api/fingerprint", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attrs, cookieId: cookie.id }),
    });
    server = await res.json();
    for (const [k, v] of Object.entries(server.serverAttrs || {})) {
      attrs[k] = v;
      extra[k] = { value: v };
      log(`  ✔ ${escapeHtml(CATALOG[k]?.label || k)}: <span class="val">${escapeHtml(short(v))}</span>`, "ok");
    }
    log(`\n✔ Huella calculada: ${server.visitorId.slice(0, 16)}…`, "head");
  } catch (e) {
    log("  ✖ No se pudo contactar al servidor. Mostrando solo resultados locales.", "warn");
  }
  await sleep(700);

  lastResult = { attrs, extra, server, cookie };
  renderResults();
}

/* ---------------- Resultados ---------------- */
function renderResults() {
  const { attrs, server, cookie } = lastResult;
  $("#scanning").hidden = true;
  $("#results").hidden = false;

  const id = server ? server.visitorId : cyrb53(Object.values(attrs).join("|"));
  const n = server ? server.devices : 1;
  const twins = server ? server.twins : 0;
  const bits = n > 0 ? Math.log2(n / (twins + 1)) : 0;

  $("#resIdenticon").innerHTML = identicon(id, 132);
  $("#resHash").textContent = `ID de huella: ${id}`;
  $("#resTitle").innerHTML = !server
    ? "Huella calculada (sin servidor)"
    : twins === 0
      ? (n > 1 ? `Tu navegador es <span class="grad">único</span> entre ${n} dispositivos del aula` : "Eres el primer dispositivo escaneado del aula")
      : `Tu huella es <span class="grad">idéntica</span> a la de ${twins} dispositivo${twins > 1 ? "s" : ""} más`;
  $("#kBits").textContent = `${bits.toFixed(1)} / ${Math.log2(Math.max(n, 1)).toFixed(1)}`;
  $("#kBits").nextElementSibling.textContent = "bits para identificarte en el aula (obtenido / máximo)";
  $("#kOneIn").textContent = twins === 0 ? "Única" : `${twins + 1} iguales`;
  $("#kOneIn").nextElementSibling.textContent = "estado de tu huella en el aula";
  $("#kClass").textContent = n;
  $("#kAttrs").textContent = Object.keys(attrs).length;

  renderBanner(server, cookie);
  renderFilters();
  renderGrid();
}

function renderBanner(server, cookie) {
  const b = $("#banner");
  if (!server) { b.innerHTML = ""; return; }
  const r = server.recognized;
  const byFp = r.byFingerprint > 0;
  const byCookie = r.byCookie;
  let cls, icon, title, text;
  if (byFp && !byCookie) {
    cls = "alert"; icon = "🚨";
    title = "¡Te reconocimos SIN cookies!";
    text = `No encontramos tu cookie (¿modo incógnito o la borraste?), pero tu huella coincide con ${r.byFingerprint} visita(s) anterior(es)
      desde ${timeAgo(r.firstSeen)}. Has usado ${r.cookiesUsed} identidades de cookie distintas y aun así sabemos que eres tú.`;
  } else if (byFp && byCookie) {
    cls = "info"; icon = "👀";
    title = "Te reconocimos por cookie… y también por tu huella";
    text = `Esta es tu visita número ${r.byFingerprint + 1}. Ahora abre esta página en una ventana de incógnito y escanea de nuevo: la cookie desaparecerá, la huella no.`;
  } else if (!byFp && byCookie) {
    cls = "info"; icon = "🧬";
    title = "Tu huella cambió, pero la cookie te delató";
    text = "Algo de tu navegador cambió (idioma, actualización, protección anti-fingerprinting…). Los rastreadores reales usan coincidencia aproximada para seguir la huella aunque cambie un poco.";
  } else {
    cls = "good"; icon = "🆕";
    title = "Primera visita registrada";
    text = "El servidor guardó tu huella. Ahora prueba: abre esta misma dirección en una ventana de incógnito (o borra cookies) y escanea otra vez.";
  }
  b.innerHTML = `<div class="banner ${cls}"><div class="big">${icon}</div><div><h3>${title}</h3><p>${text}</p></div></div>`;
}

function renderFilters() {
  const present = new Set(Object.keys(lastResult.attrs).map(k => CATALOG[k]?.cat).filter(Boolean));
  const chips = [["all", "Todo", "✨"], ...Object.entries(CATEGORIES).filter(([k]) => present.has(k)).map(([k, c]) => [k, c.label, c.icon])];
  $("#filters").innerHTML = chips.map(([k, label, icon]) =>
    `<button class="chip ${activeFilter === k ? "active" : ""}" data-f="${k}">${icon} ${label}</button>`).join("");
  $("#filters").querySelectorAll(".chip").forEach(ch => ch.addEventListener("click", () => {
    activeFilter = ch.dataset.f;
    renderFilters();
    renderGrid();
  }));
}

function attrBits(key) {
  const s = lastResult.server?.stats?.[key];
  return s ? s : { same: 1, total: 1, bits: 0 };
}

function renderGrid() {
  const { attrs, extra, server } = lastResult;
  const stable = new Set(server?.stableKeys || []);
  const maxClass = Math.max(1, Math.log2(server?.devices || 1));
  const keys = Object.keys(attrs).filter(k => activeFilter === "all" || CATALOG[k]?.cat === activeFilter);

  $("#attrGrid").innerHTML = keys.map((k, i) => {
    const meta = CATALOG[k] || { label: k, cat: "navegador", ref: 0 };
    const cat = CATEGORIES[meta.cat];
    const st = attrBits(k);
    const tags = [
      stable.has(k) ? `<span class="pill ok">🔑 usado en el ID</span>` : meta.volatile ? `<span class="pill warn">⏱ volátil</span>` : `<span class="pill">fuera del ID</span>`,
      meta.passive ? `<span class="pill violet">pasivo</span>` : "",
      st.total > 1 ? (st.same === 1 ? `<span class="pill danger">solo tú</span>` : `<span class="pill">${st.same}/${st.total} lo comparten</span>`) : "",
    ].join("");
    const img = extra[k]?.image ? `<img src="${extra[k].image}" alt="Imagen dibujada en el canvas">` : "";
    return `<button class="attr" data-k="${k}" style="animation-delay:${i * 25}ms">
      <div class="top"><span class="ico">${cat.icon}</span><span class="name">${escapeHtml(meta.label)}</span></div>
      ${img}
      <div class="value" title="${escapeHtml(attrs[k])}">${escapeHtml(extra[k]?.display ?? attrs[k])}</div>
      <div class="tags">${tags}</div>
      <div class="meter"><span>Aula</span><span class="bar"><i class="cls" style="width:${(st.bits / maxClass) * 100}%"></i></span><b>${st.bits.toFixed(1)} b</b></div>
      <div class="meter"><span>Mundo ≈</span><span class="bar"><i class="ref" style="width:${(meta.ref / 16) * 100}%"></i></span><b>${meta.ref.toFixed(1)} b</b></div>
    </button>`;
  }).join("");

  $("#attrGrid").querySelectorAll(".attr").forEach(el => el.addEventListener("click", () => openDetail(el.dataset.k)));
}

/* ---------------- Detalle (modal) ---------------- */
function openDetail(key) {
  const { attrs, extra, server } = lastResult;
  const meta = CATALOG[key] || { label: key, cat: "navegador", what: "", why: "", defense: "", ref: 0 };
  const st = attrBits(key);
  const stable = (server?.stableKeys || []).includes(key);
  $("#dIco").textContent = CATEGORIES[meta.cat].icon;
  $("#dTitle").textContent = meta.label;
  const dots = st.total > 1
    ? `<div class="share-dots">${Array.from({ length: Math.min(st.total, 120) }, (_, i) => `<i class="${i < st.same ? "on" : ""}"></i>`).join("")}</div>
       <p class="muted" style="font-size:.85rem;margin-top:6px">${st.same} de ${st.total} dispositivos del aula tienen este mismo valor →
       −log₂(${st.same}/${st.total}) = <b>${st.bits.toFixed(2)} bits</b></p>`
    : `<p class="muted">Cuando más compañeros escaneen, aquí verás cuántos comparten tu valor.</p>`;
  $("#dBody").innerHTML = `
    ${extra[key]?.image ? `<img src="${extra[key].image}" style="width:100%;border-radius:10px" alt="">` : ""}
    <div class="block"><h4>Tu valor</h4><div class="rawval">${escapeHtml(attrs[key])}</div></div>
    <div class="block"><h4>¿Qué es?</h4><p>${meta.what}</p></div>
    <div class="block"><h4>¿Por qué te identifica?</h4><p>${meta.why}</p></div>
    <div class="block"><h4>¿Cómo protegerte?</h4><p>${meta.defense}</p></div>
    <div class="block"><h4>En el aula</h4>${dots}</div>
    <div class="block"><h4>Uso en el rastreo</h4><p>${stable
      ? "🔑 Es <b>estable</b>: no cambia al borrar cookies ni en incógnito, por eso forma parte del ID de huella."
      : meta.volatile
        ? "⏱ Es <b>volátil</b>: cambia con facilidad (zoom, red, tamaño de ventana), así que no se usa para el ID permanente."
        : "No forma parte del ID: aporta poca información o puede variar entre modo normal e incógnito."}
      ${meta.passive ? " Además es <b>pasivo</b>: el servidor lo ve sin ejecutar JavaScript." : ""}</p></div>`;
  $("#detail").showModal();
}
$("#dClose").addEventListener("click", () => $("#detail").close());
$("#detail").addEventListener("click", e => { if (e.target === $("#detail")) $("#detail").close(); });

/* ---------------- Calculadora de entropía ---------------- */
(function initCalc() {
  const items = Object.entries(CATALOG).filter(([, m]) => m.ref >= 1).sort((a, b) => b[1].ref - a[1].ref);
  const defaults = new Set(["ua", "canvas", "fonts", "timezone", "screen"]);
  $("#calcList").innerHTML = items.map(([k, m]) =>
    `<label><input type="checkbox" value="${m.ref}" ${defaults.has(k) ? "checked" : ""}><span>${CATEGORIES[m.cat].icon} ${m.label}</span><em>${m.ref.toFixed(1)}</em></label>`).join("");
  const fmt = new Intl.NumberFormat("es-CO", { maximumFractionDigits: 0 });
  const update = () => {
    const bits = Array.from($("#calcList").querySelectorAll("input:checked")).reduce((s, i) => s + parseFloat(i.value), 0);
    const people = Math.pow(2, bits);
    $("#calcBits").textContent = `${bits.toFixed(1)} bits`;
    $("#calcPeople").innerHTML = bits >= 33
      ? `≈ 1 de cada <b>${people > 1e12 ? people.toExponential(1) : fmt.format(people)}</b> personas<br><span style="color:var(--danger);font-weight:700">¡Más que la población mundial: identificable!</span>`
      : `≈ 1 de cada <b>${fmt.format(people)}</b> personas comparte esta combinación`;
    $("#calcBar").style.width = `${Math.min(bits / 40, 1) * 100}%`;
  };
  $("#calcList").addEventListener("change", update);
  update();
})();

/* ---------------- Experimentos ---------------- */
const EXPERIMENTS = [
  {
    icon: "🕶️", title: "Modo incógnito", level: "Básico",
    steps: ["Abre una ventana de incógnito / privada.", "Entra a la misma dirección del aula.", "Escanea de nuevo."],
    answer: "En Chrome, Edge y Firefox la cookie desaparece pero la huella es la misma: verás la alerta roja «¡Te reconocimos SIN cookies!». En Safari el modo privado añade ruido al canvas y al audio, por eso puede que NO te reconozca: ¡una defensa en acción!",
  },
  {
    icon: "🍪", title: "Borrar cookies", level: "Básico",
    steps: ["Borra cookies y datos del sitio (configuración del navegador).", "Recarga la página y escanea."],
    answer: "Igual que en incógnito: el identificador por cookie se pierde, pero la huella sigue intacta. Borrar cookies NO protege contra el fingerprinting.",
  },
  {
    icon: "🔍", title: "Cambiar el zoom o la ventana", level: "Básico",
    steps: ["Pulsa Ctrl/Cmd + '+' dos veces o cambia el tamaño de la ventana.", "Escanea de nuevo y compara 'Densidad de píxeles' y 'Tamaño de ventana'."],
    answer: "Esos atributos cambian, pero son volátiles y no forman parte del ID, así que te siguen reconociendo. Un rastreador bien diseñado separa los datos estables de los volátiles.",
  },
  {
    icon: "🌐", title: "Cambiar de red o usar VPN", level: "Intermedio",
    steps: ["Si el aula lo permite, conéctate por otra red o activa una VPN.", "Escanea de nuevo."],
    answer: "La IP cambia, pero la huella no depende de la IP. Una VPN oculta tu ubicación de red, no tu navegador. (Nota: si te sales de la red del aula no llegarás al servidor del docente).",
  },
  {
    icon: "🔀", title: "Otro navegador, mismo equipo", level: "Intermedio",
    steps: ["Abre la página con un navegador diferente (Chrome ↔ Firefox ↔ Edge).", "Escanea y mira qué atributos coinciden."],
    answer: "El ID cambia porque cambian User-Agent, canvas y WebGL. Pero pantalla, zona horaria, núcleos, fuentes y GPU suelen coincidir: existen técnicas de 'cross-browser fingerprinting' que reconocen el EQUIPO aunque cambies de navegador.",
  },
  {
    icon: "🌎", title: "Cambiar el idioma", level: "Intermedio",
    steps: ["Agrega o reordena un idioma en la configuración del navegador.", "Escanea de nuevo."],
    answer: "Un pequeño cambio rompe la coincidencia exacta del ID, pero la cookie todavía te reconoce. Los rastreadores reales (ej. FP-Stalker) usan coincidencia aproximada para seguir la evolución de la huella.",
  },
  {
    icon: "🦁", title: "Brave o Tor Browser", level: "Avanzado",
    steps: ["Escanea con Brave (escudos activados) o Tor Browser.", "Escanea dos veces: en sesiones distintas."],
    answer: "Brave aleatoriza canvas, audio y WebGL: obtendrás una huella distinta por sesión (aleatorización). Tor hace que todos los usuarios se vean iguales (uniformidad): pantalla redondeada, UTC, inglés, sin WebGL detallado.",
  },
  {
    icon: "🖥️", title: "Sala de cómputo idéntica", level: "Discusión",
    steps: ["Si estás en una sala con equipos iguales, escanead varios.", "Mirad en el panel docente si aparecen huellas compartidas."],
    answer: "Equipos clonados con la misma imagen pueden tener huella idéntica: el fingerprinting no es infalible. En la práctica los rastreadores lo combinan con IP, comportamiento y cookies para desempatar.",
  },
];
$("#expGrid").innerHTML = EXPERIMENTS.map((e, i) => `
  <article class="card exp">
    <div class="head"><span class="big">${e.icon}</span><div><span class="pill">${i + 1} · ${e.level}</span><h3 style="margin:4px 0 0">${e.title}</h3></div></div>
    <ol>${e.steps.map(s => `<li>${s}</li>`).join("")}</ol>
    <details><summary>Ver qué debería pasar</summary><p>${e.answer}</p></details>
  </article>`).join("");

/* ---------------- Arranque ---------------- */
$("#startBtn").addEventListener("click", runScan);
$("#rescanBtn").addEventListener("click", runScan);
if (new URLSearchParams(location.search).has("auto")) runScan();
