// Panel en vivo del docente: se actualiza cada pocos segundos.

const $ = sel => document.querySelector(sel);
const REFRESH_MS = 3000;

async function loadInfo() {
  try {
    const info = await (await fetch("/api/info")).json();
    $("#joinUrl").textContent = info.url;
    if (window.QRCode) {
      $("#qr").innerHTML = "";
      new QRCode($("#qr"), { text: info.url, width: 152, height: 152, correctLevel: QRCode.CorrectLevel.M });
    } else {
      $("#qr").innerHTML = `<span style="color:#555;font-size:.75rem;text-align:center">QR no disponible sin internet.<br>Usa la dirección →</span>`;
    }
    if (!info.isLocal) $("#resetBtn").hidden = true;
  } catch (e) {
    $("#joinUrl").textContent = "Servidor no disponible";
  }
}

function renderVisitors(rows) {
  if (!rows.length) {
    $("#visList").innerHTML = `<div class="empty">Esperando el primer escaneo…<br><span style="font-size:2.4rem">📡</span></div>`;
    return;
  }
  $("#visList").innerHTML = rows.map(r => {
    const ua = describeUA(r.ua);
    const tags = [
      r.shared ? `<span class="pill warn">🧬 huella compartida ×${r.shared + 1}</span>` : `<span class="pill ok">única</span>`,
      r.cookies > 1 ? `<span class="pill danger">🚨 ${r.cookies} cookies, misma huella</span>` : "",
      r.visits > 1 ? `<span class="pill">${r.visits} escaneos</span>` : "",
    ].join(" ");
    return `<div class="vis">
      ${identicon(r.visitorId, 44)}
      <div>
        <div class="name">${ua.icon} ${escapeHtml(ua.text)} <span class="mono muted" style="font-size:.75rem">#${r.visitorId.slice(0, 8)}</span></div>
        <div class="meta">${escapeHtml(r.screen)} · ${escapeHtml(r.timezone)} · ${escapeHtml(r.ip)}</div>
        <div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap">${tags}</div>
      </div>
      <div class="meta">${timeAgo(r.lastSeen)}</div>
    </div>`;
  }).join("");
}

function renderEntropy(list, maxH) {
  $("#maxH").textContent = maxH.toFixed(2);
  if (!list.length) {
    $("#entropyList").innerHTML = `<div class="empty">Sin datos todavía.</div>`;
    return;
  }
  const scale = Math.max(maxH, 1);
  $("#entropyList").innerHTML = list.map(e => {
    const meta = CATALOG[e.key] || { label: e.key, cat: "navegador" };
    return `<div class="ent-row" title="${e.distinct} valores distintos">
      <span>${CATEGORIES[meta.cat]?.icon || ""} ${escapeHtml(meta.label)}</span>
      <span class="bar"><i class="${e.stable ? "" : "vol"}" style="width:${(e.entropy / scale) * 100}%"></i></span>
      <b>${e.entropy.toFixed(2)}</b>
    </div>`;
  }).join("");
}

async function refresh() {
  try {
    const d = await (await fetch("/api/panel")).json();
    $("#sDevices").textContent = d.devices;
    $("#sUnique").textContent = d.devices ? `${Math.round((d.uniqueDevices / d.devices) * 100)} %` : "0 %";
    $("#sVisits").textContent = d.visits;
    $("#sNoCookie").textContent = d.recognizedWithoutCookie;
    renderVisitors(d.rows);
    renderEntropy(d.entropy, d.maxEntropy);
    $("#updated").textContent = `actualizado ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    $("#updated").textContent = "⚠ sin conexión con el servidor";
  }
}

$("#resetBtn").addEventListener("click", async () => {
  if (!confirm("¿Borrar todos los escaneos de la clase? Esta acción no se puede deshacer.")) return;
  await fetch("/api/reset", { method: "POST" });
  refresh();
});

loadInfo();
refresh();
setInterval(refresh, REFRESH_MS);
