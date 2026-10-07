// Utilidades compartidas entre el escáner y el panel docente.

// Hash rápido no criptográfico (cyrb53). Se usa en el navegador porque
// crypto.subtle solo existe en contextos seguros (https / localhost) y los
// estudiantes entran por http://IP-del-docente.
function cyrb53(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h2 >>> 0).toString(16).padStart(8, "0") + (h1 >>> 0).toString(16).padStart(8, "0");
}

// Identicon simétrico 5x5 a partir de un hash hexadecimal: la "cara" de la huella.
function identicon(hex, size = 64) {
  hex = (hex || "0").padEnd(32, "0");
  const hue = parseInt(hex.slice(0, 3), 16) % 360;
  const hue2 = (hue + 140) % 360;
  let cells = "";
  const cell = size / 5;
  for (let y = 0; y < 5; y++) {
    for (let x = 0; x < 3; x++) {
      const nib = parseInt(hex[(y * 3 + x) % hex.length], 16);
      if (nib % 2 === 0) continue;
      const color = nib > 8 ? `hsl(${hue} 85% 60%)` : `hsl(${hue2} 80% 62%)`;
      for (const cx of new Set([x, 4 - x])) {
        cells += `<rect x="${cx * cell}" y="${y * cell}" width="${cell}" height="${cell}" rx="${cell * 0.18}" fill="${color}"/>`;
      }
    }
  }
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" aria-hidden="true">` +
    `<rect width="${size}" height="${size}" rx="${size * 0.16}" fill="hsl(${hue} 40% 14%)"/>${cells}</svg>`;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Resumen legible del User-Agent (solo para mostrar).
function describeUA(ua = "") {
  let browser = "Navegador";
  if (/Edg\//.test(ua)) browser = "Edge";
  else if (/OPR\//.test(ua)) browser = "Opera";
  else if (/Firefox\//.test(ua)) browser = "Firefox";
  else if (/Chrome\//.test(ua)) browser = "Chrome";
  else if (/Safari\//.test(ua)) browser = "Safari";
  let os = "";
  if (/iPhone|iPad/.test(ua)) os = "iOS";
  else if (/Android/.test(ua)) os = "Android";
  else if (/Mac OS X/.test(ua)) os = "macOS";
  else if (/Windows/.test(ua)) os = "Windows";
  else if (/Linux/.test(ua)) os = "Linux";
  const icon = /iPhone|Android.*Mobile/.test(ua) ? "📱" : /iPad|Android/.test(ua) ? "📲" : "💻";
  return { browser, os, icon, text: `${browser}${os ? " · " + os : ""}` };
}

function timeAgo(ts) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `hace ${s} s`;
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  return `hace ${Math.round(s / 3600)} h`;
}

// Tema claro/oscuro (oscuro por defecto; el claro va mejor con algunos proyectores).
(function initTheme() {
  try {
    const saved = localStorage.getItem("fp-theme");
    if (saved) document.documentElement.dataset.theme = saved;
  } catch (e) { /* almacenamiento bloqueado */ }
  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("themeToggle");
    if (!btn) return;
    btn.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("fp-theme", next); } catch (e) { /* ignorar */ }
    });
  });
})();
